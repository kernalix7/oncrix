// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM Generic Interrupt Controller (GIC) v2 and v3 hardware driver.
//!
//! Implements the Distributor, CPU Interface, and Redistributor registers
//! for GICv2 and GICv3. Used on ARM Cortex-A and Neoverse platforms.
//!
//! # GICv2 Register Layout
//!
//! | Base       | Component             |
//! |------------|-----------------------|
//! | GICD_BASE  | Distributor           |
//! | GICC_BASE  | CPU Interface         |
//!
//! # GICv3 Register Layout
//!
//! | Base       | Component             |
//! |------------|-----------------------|
//! | GICD_BASE  | Distributor           |
//! | GICR_BASE  | Redistributor (×NCPU) |
//! | (ICC_* SRs)| CPU Interface (sys regs) |
//!
//! # Interrupt ID Ranges
//!
//! - **SGI**: 0–15 (Software Generated Interrupts)
//! - **PPI**: 16–31 (Private Peripheral Interrupts, per CPU)
//! - **SPI**: 32–1019 (Shared Peripheral Interrupts)
//! - **LPI**: ≥8192 (Locality-specific Peripheral Interrupts, GICv3 only)
//!
//! Reference: ARM IHI0048B (GICv2 Architecture), ARM IHI0069H (GICv3/v4 Architecture).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of GIC instances.
pub const MAX_GIC_INSTANCES: usize = 2;
/// Maximum SPIs supported (GICv2: 480, GICv3: 988).
pub const MAX_SPI: usize = 1020;
/// SGI count.
pub const SGI_COUNT: usize = 16;
/// PPI count.
pub const PPI_COUNT: usize = 16;

// ---------------------------------------------------------------------------
// GIC Distributor Register Offsets (GICD_*)
// ---------------------------------------------------------------------------

/// GICD_CTLR — Distributor Control Register.
const GICD_CTLR: u32 = 0x000;
/// GICD_TYPER — Interrupt Controller Type Register.
const GICD_TYPER: u32 = 0x004;
/// GICD_IIDR — Distributor Implementer Identification Register.
const _GICD_IIDR: u32 = 0x008;
/// GICD_ISENABLER0 — Interrupt Set-Enable Registers base.
const GICD_ISENABLER: u32 = 0x100;
/// GICD_ICENABLER0 — Interrupt Clear-Enable Registers base.
const GICD_ICENABLER: u32 = 0x180;
/// GICD_ISPENDR0 — Interrupt Set-Pending Registers base.
const _GICD_ISPENDR: u32 = 0x200;
/// GICD_ICPENDR0 — Interrupt Clear-Pending Registers base.
const GICD_ICPENDR: u32 = 0x280;
/// GICD_ISACTIVER0 — Interrupt Set-Active Registers base.
const _GICD_ISACTIVER: u32 = 0x300;
/// GICD_IPRIORITYR0 — Interrupt Priority Registers base.
const GICD_IPRIORITYR: u32 = 0x400;
/// GICD_ITARGETSR0 — Interrupt Processor Targets Registers base (GICv2).
const GICD_ITARGETSR: u32 = 0x800;
/// GICD_ICFGR0 — Interrupt Configuration Registers base.
const _GICD_ICFGR: u32 = 0xC00;
/// GICD_SGIR — Software Generated Interrupt Register (GICv2).
const GICD_SGIR: u32 = 0xF00;

// ---------------------------------------------------------------------------
// GIC CPU Interface Register Offsets (GICC_*) — GICv2 only
// ---------------------------------------------------------------------------

/// GICC_CTLR — CPU Interface Control Register.
const GICC_CTLR: u32 = 0x000;
/// GICC_PMR — Interrupt Priority Mask Register.
const GICC_PMR: u32 = 0x004;
/// GICC_BPR — Binary Point Register.
const _GICC_BPR: u32 = 0x008;
/// GICC_IAR — Interrupt Acknowledge Register.
const GICC_IAR: u32 = 0x00C;
/// GICC_EOIR — End of Interrupt Register.
const GICC_EOIR: u32 = 0x010;
/// GICC_RPR — Running Priority Register.
const _GICC_RPR: u32 = 0x014;
/// GICC_HPPIR — Highest Priority Pending Interrupt Register.
const _GICC_HPPIR: u32 = 0x018;

// ---------------------------------------------------------------------------
// GICD_CTLR bits
// ---------------------------------------------------------------------------

/// GICD_CTLR: Enable Group 0 (GICv2) / EnableGrp0 (GICv3).
const GICD_CTLR_ENABLE_G0: u32 = 1 << 0;
/// GICD_CTLR: Enable Group 1 (GICv2).
const GICD_CTLR_ENABLE_G1: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// GIC Version
// ---------------------------------------------------------------------------

/// GIC architecture version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicVersion {
    /// ARM GICv2.
    V2,
    /// ARM GICv3.
    V3,
}

// ---------------------------------------------------------------------------
// Interrupt trigger mode
// ---------------------------------------------------------------------------

/// Interrupt trigger configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerMode {
    /// Level-sensitive (default).
    Level,
    /// Edge-triggered.
    Edge,
}

// ---------------------------------------------------------------------------
// GIC hardware struct
// ---------------------------------------------------------------------------

/// ARM GIC hardware instance.
pub struct GicHw {
    /// Distributor MMIO base.
    gicd_base: u64,
    /// CPU Interface MMIO base (GICv2 only; 0 for GICv3).
    gicc_base: u64,
    /// Redistributor MMIO base (GICv3 only; 0 for GICv2).
    gicr_base: u64,
    /// GIC version.
    version: GicVersion,
    /// Number of interrupt lines (as reported by GICD_TYPER).
    num_irqs: usize,
    /// Whether this instance is initialized.
    initialized: bool,
}

impl GicHw {
    /// Creates a new GICv2 instance.
    pub const fn new_v2(gicd_base: u64, gicc_base: u64) -> Self {
        Self {
            gicd_base,
            gicc_base,
            gicr_base: 0,
            version: GicVersion::V2,
            num_irqs: 0,
            initialized: false,
        }
    }

    /// Creates a new GICv3 instance.
    pub const fn new_v3(gicd_base: u64, gicr_base: u64) -> Self {
        Self {
            gicd_base,
            gicc_base: 0,
            gicr_base,
            version: GicVersion::V3,
            num_irqs: 0,
            initialized: false,
        }
    }

    /// Initializes the GIC distributor and CPU interface.
    ///
    /// Disables all SPIs, sets default priority 0xA0, and enables the
    /// distributor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the MMIO base is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.gicd_base == 0 {
            return Err(Error::InvalidArgument);
        }

        // Disable distributor while configuring.
        self.write_gicd(GICD_CTLR, 0);

        // Read number of IRQ lines.
        let typer = self.read_gicd(GICD_TYPER);
        self.num_irqs = ((typer & 0x1F) as usize + 1) * 32;
        if self.num_irqs > MAX_SPI {
            self.num_irqs = MAX_SPI;
        }

        // Disable all SPIs (bit-per-irq in ICENABLER).
        let num_regs = (self.num_irqs + 31) / 32;
        for i in 0..num_regs {
            self.write_gicd(GICD_ICENABLER + i as u32 * 4, 0xFFFF_FFFF);
            self.write_gicd(GICD_ICPENDR + i as u32 * 4, 0xFFFF_FFFF);
        }

        // Set default priority 0xA0 for all SPIs.
        let num_prio_regs = (self.num_irqs + 3) / 4;
        for i in 0..num_prio_regs {
            self.write_gicd(GICD_IPRIORITYR + i as u32 * 4, 0xA0A0_A0A0);
        }

        // Target all SPIs to CPU0 (GICv2 only).
        if self.version == GicVersion::V2 {
            let num_target_regs = (self.num_irqs + 3) / 4;
            // Start from IRQ 32 (SPIs start at 32).
            for i in 8..num_target_regs {
                self.write_gicd(GICD_ITARGETSR + i as u32 * 4, 0x0101_0101);
            }
        }

        // Enable distributor (Group 0 + Group 1).
        self.write_gicd(GICD_CTLR, GICD_CTLR_ENABLE_G0 | GICD_CTLR_ENABLE_G1);

        // Enable CPU interface (GICv2 only).
        if self.version == GicVersion::V2 && self.gicc_base != 0 {
            // Allow all priorities.
            self.write_gicc(GICC_PMR, 0xFF);
            // Enable CPU interface.
            self.write_gicc(GICC_CTLR, 0x1);
        }

        self.initialized = true;
        Ok(())
    }

    /// Enables an interrupt by IRQ number.
    pub fn enable_irq(&self, irq: u32) {
        let reg = GICD_ISENABLER + (irq / 32) * 4;
        let bit = 1u32 << (irq % 32);
        self.write_gicd(reg, bit);
    }

    /// Disables an interrupt by IRQ number.
    pub fn disable_irq(&self, irq: u32) {
        let reg = GICD_ICENABLER + (irq / 32) * 4;
        let bit = 1u32 << (irq % 32);
        self.write_gicd(reg, bit);
    }

    /// Sets the priority for an interrupt (0 = highest, 0xFF = lowest).
    pub fn set_priority(&self, irq: u32, priority: u8) {
        let reg = GICD_IPRIORITYR + irq;
        // Byte-access: read-modify-write the 32-bit register.
        let shift = (irq % 4) * 8;
        let mask = !(0xFFu32 << shift);
        let word_reg = GICD_IPRIORITYR + (irq / 4) * 4;
        let val = (self.read_gicd(word_reg) & mask) | ((priority as u32) << shift);
        self.write_gicd(word_reg, val);
        let _ = reg;
    }

    /// Sends an SGI (Software Generated Interrupt) to the target CPUs (GICv2).
    ///
    /// `target_list` is a bitmask of target CPU interfaces.
    pub fn send_sgi(&self, sgi_id: u8, target_list: u8) {
        // GICD_SGIR: [25:24]=TargetListFilter=0 (use list), [23:16]=CPUTargetList,
        //            [15]=NSATT, [3:0]=SGIINTID.
        let val = ((target_list as u32) << 16) | (sgi_id as u32 & 0xF);
        self.write_gicd(GICD_SGIR, val);
    }

    /// Acknowledges a pending interrupt (GICv2).
    ///
    /// Returns the interrupt ID. 1023 means spurious.
    pub fn ack_irq(&self) -> u32 {
        self.read_gicc(GICC_IAR) & 0x3FF
    }

    /// Signals end-of-interrupt for the given IRQ ID (GICv2).
    pub fn eoi(&self, irq: u32) {
        self.write_gicc(GICC_EOIR, irq & 0x3FF);
    }

    /// Returns the number of interrupt lines.
    pub fn num_irqs(&self) -> usize {
        self.num_irqs
    }

    /// Returns the GIC version.
    pub fn version(&self) -> GicVersion {
        self.version
    }

    /// Returns whether the GIC is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -----------------------------------------------------------------------
    // Private MMIO helpers
    // -----------------------------------------------------------------------

    fn read_gicd(&self, offset: u32) -> u32 {
        let addr = (self.gicd_base + offset as u64) as *const u32;
        // SAFETY: gicd_base is a valid GIC Distributor MMIO region.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write_gicd(&self, offset: u32, val: u32) {
        let addr = (self.gicd_base + offset as u64) as *mut u32;
        // SAFETY: gicd_base is a valid GIC Distributor MMIO region.
        unsafe { core::ptr::write_volatile(addr, val) }
    }

    fn read_gicc(&self, offset: u32) -> u32 {
        let addr = (self.gicc_base + offset as u64) as *const u32;
        // SAFETY: gicc_base is a valid GIC CPU Interface MMIO region.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write_gicc(&self, offset: u32, val: u32) {
        let addr = (self.gicc_base + offset as u64) as *mut u32;
        // SAFETY: gicc_base is a valid GIC CPU Interface MMIO region.
        unsafe { core::ptr::write_volatile(addr, val) }
    }
}

impl Default for GicHw {
    fn default() -> Self {
        Self::new_v2(0, 0)
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Global GIC instance registry.
pub struct GicRegistry {
    instances: [GicHw; MAX_GIC_INSTANCES],
    count: usize,
}

impl GicRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            instances: [const { GicHw::new_v2(0, 0) }; MAX_GIC_INSTANCES],
            count: 0,
        }
    }

    /// Registers a GICv2 instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register_v2(&mut self, gicd_base: u64, gicc_base: u64) -> Result<usize> {
        if self.count >= MAX_GIC_INSTANCES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.instances[idx] = GicHw::new_v2(gicd_base, gicc_base);
        self.count += 1;
        Ok(idx)
    }

    /// Registers a GICv3 instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register_v3(&mut self, gicd_base: u64, gicr_base: u64) -> Result<usize> {
        if self.count >= MAX_GIC_INSTANCES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.instances[idx] = GicHw::new_v3(gicd_base, gicr_base);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to the instance at `index`.
    pub fn get(&self, index: usize) -> Option<&GicHw> {
        if index < self.count {
            Some(&self.instances[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the instance at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut GicHw> {
        if index < self.count {
            Some(&mut self.instances[index])
        } else {
            None
        }
    }

    /// Returns the number of registered instances.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no instances are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for GicRegistry {
    fn default() -> Self {
        Self::new()
    }
}
