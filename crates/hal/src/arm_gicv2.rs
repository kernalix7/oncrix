// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM Generic Interrupt Controller v2 (GICv2) driver.
//!
//! Implements the GICv2 interrupt controller found in ARM Cortex-A systems.
//! Manages the Distributor (GICD) and CPU Interface (GICC) registers.
//!
//! # Architecture
//!
//! GICv2 has two main components:
//! - **Distributor (GICD)**: Routes interrupts to CPU interfaces, manages priority and targeting
//! - **CPU Interface (GICC)**: Per-CPU registers for interrupt acknowledgement and EOI
//!
//! # Interrupt Types
//!
//! - SGI (Software Generated Interrupts): IDs 0–15, used for IPI
//! - PPI (Private Peripheral Interrupts): IDs 16–31, per-CPU peripherals
//! - SPI (Shared Peripheral Interrupts): IDs 32–1019, shared among CPUs

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Maximum number of interrupt lines supported by GICv2.
pub const GIC_MAX_IRQS: usize = 1020;

/// Maximum number of CPUs GICv2 can target.
pub const GIC_MAX_CPUS: usize = 8;

/// SGI interrupt ID range.
pub const GIC_SGI_BASE: u32 = 0;
pub const GIC_SGI_MAX: u32 = 15;

/// PPI interrupt ID range.
pub const GIC_PPI_BASE: u32 = 16;
pub const GIC_PPI_MAX: u32 = 31;

/// SPI interrupt ID range.
pub const GIC_SPI_BASE: u32 = 32;

// Distributor register offsets
const GICD_CTLR: usize = 0x000;
const GICD_TYPER: usize = 0x004;
const GICD_IIDR: usize = 0x008;
const GICD_IGROUPR: usize = 0x080;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_ISPENDR: usize = 0x200;
const GICD_ICPENDR: usize = 0x280;
const GICD_ISACTIVER: usize = 0x300;
const GICD_ICACTIVER: usize = 0x380;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ITARGETSR: usize = 0x800;
const GICD_ICFGR: usize = 0xC00;
const GICD_SGIR: usize = 0xF00;

// CPU Interface register offsets
const GICC_CTLR: usize = 0x000;
const GICC_PMR: usize = 0x004;
const GICC_BPR: usize = 0x008;
const GICC_IAR: usize = 0x00C;
const GICC_EOIR: usize = 0x010;
const GICC_RPR: usize = 0x014;
const GICC_HPPIR: usize = 0x018;
const GICC_ABPR: usize = 0x01C;
const GICC_IIDR: usize = 0x0FC;

/// Interrupt trigger mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerMode {
    /// Level-sensitive interrupt.
    Level,
    /// Edge-triggered interrupt.
    Edge,
}

/// GICv2 SGI target filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SgiTarget {
    /// Send to specified CPUs by affinity mask.
    CpuMask(u8),
    /// Send to all CPUs except the sender.
    OtherCpus,
    /// Send only to the sending CPU.
    Self_,
}

/// GICv2 distributor and CPU interface controller.
pub struct ArmGicV2 {
    /// Base address of the GIC Distributor (MMIO).
    gicd_base: usize,
    /// Base address of the GIC CPU Interface (MMIO).
    gicc_base: usize,
    /// Number of interrupt lines (IT lines * 32).
    num_irqs: u32,
    /// Number of implemented CPUs.
    num_cpus: u32,
    /// Whether the GIC has been initialized.
    initialized: bool,
}

impl ArmGicV2 {
    /// Creates a new GICv2 instance with the given MMIO base addresses.
    ///
    /// # Arguments
    ///
    /// * `gicd_base` - Physical base address of the GIC Distributor
    /// * `gicc_base` - Physical base address of the GIC CPU Interface
    pub const fn new(gicd_base: usize, gicc_base: usize) -> Self {
        Self {
            gicd_base,
            gicc_base,
            num_irqs: 0,
            num_cpus: 0,
            initialized: false,
        }
    }

    /// Initializes the GICv2 controller.
    ///
    /// Reads hardware capabilities, configures the distributor and CPU interface.
    /// Must be called before any interrupt management operations.
    pub fn init(&mut self) -> Result<()> {
        // Read GICD_TYPER to determine IRQ and CPU counts
        let typer = self.gicd_read32(GICD_TYPER);
        self.num_irqs = ((typer & 0x1F) + 1) * 32;
        self.num_cpus = ((typer >> 5) & 0x7) + 1;

        if self.num_irqs as usize > GIC_MAX_IRQS {
            return Err(Error::InvalidArgument);
        }

        // Disable distributor during setup
        self.gicd_write32(GICD_CTLR, 0);

        // Set all SPIs to lowest priority
        let spi_count = (self.num_irqs - GIC_SPI_BASE) as usize;
        for i in 0..spi_count {
            let offset = GICD_IPRIORITYR + (GIC_SPI_BASE as usize / 4 * 4) + i * 4;
            self.gicd_write32(offset, 0xA0A0A0A0);
        }

        // Set all SPIs to target CPU 0
        for i in 0..(spi_count / 4) {
            let offset = GICD_ITARGETSR + (GIC_SPI_BASE as usize + i * 4);
            self.gicd_write32(offset, 0x01010101);
        }

        // Disable all SPIs
        for i in 0..(self.num_irqs / 32) {
            self.gicd_write32(GICD_ICENABLER + (i as usize * 4), 0xFFFF_FFFF);
        }

        // Enable the distributor
        self.gicd_write32(GICD_CTLR, 1);

        // Configure CPU interface: enable, pass all priorities
        self.gicc_write32(GICC_PMR, 0xF0);
        self.gicc_write32(GICC_BPR, 0x0);
        self.gicc_write32(GICC_CTLR, 1);

        self.initialized = true;
        Ok(())
    }

    /// Enables an interrupt line.
    pub fn enable_irq(&self, irq: u32) -> Result<()> {
        self.check_irq(irq)?;
        let reg = irq / 32;
        let bit = irq % 32;
        self.gicd_write32(GICD_ISENABLER + (reg as usize * 4), 1 << bit);
        Ok(())
    }

    /// Disables an interrupt line.
    pub fn disable_irq(&self, irq: u32) -> Result<()> {
        self.check_irq(irq)?;
        let reg = irq / 32;
        let bit = irq % 32;
        self.gicd_write32(GICD_ICENABLER + (reg as usize * 4), 1 << bit);
        Ok(())
    }

    /// Sets the priority of an interrupt (0 = highest, 0xFF = lowest).
    pub fn set_priority(&self, irq: u32, priority: u8) -> Result<()> {
        self.check_irq(irq)?;
        let byte_offset = GICD_IPRIORITYR + irq as usize;
        // Read-modify-write: only touch the relevant byte
        let word_offset = byte_offset & !3;
        let byte_pos = byte_offset & 3;
        let mut val = self.gicd_read32(word_offset);
        val &= !(0xFF << (byte_pos * 8));
        val |= (priority as u32) << (byte_pos * 8);
        self.gicd_write32(word_offset, val);
        Ok(())
    }

    /// Configures the trigger mode of an interrupt.
    pub fn set_trigger(&self, irq: u32, mode: TriggerMode) -> Result<()> {
        if irq < GIC_SPI_BASE {
            return Err(Error::InvalidArgument);
        }
        self.check_irq(irq)?;
        let reg = irq / 16;
        let bit = (irq % 16) * 2 + 1;
        let mut val = self.gicd_read32(GICD_ICFGR + (reg as usize * 4));
        match mode {
            TriggerMode::Edge => val |= 1 << bit,
            TriggerMode::Level => val &= !(1 << bit),
        }
        self.gicd_write32(GICD_ICFGR + (reg as usize * 4), val);
        Ok(())
    }

    /// Sends a Software Generated Interrupt (SGI) for inter-processor communication.
    pub fn send_sgi(&self, irq: u32, target: SgiTarget) -> Result<()> {
        if irq > GIC_SGI_MAX {
            return Err(Error::InvalidArgument);
        }
        let (filter, cpu_mask) = match target {
            SgiTarget::CpuMask(mask) => (0u32, mask as u32),
            SgiTarget::OtherCpus => (1u32, 0u32),
            SgiTarget::Self_ => (2u32, 0u32),
        };
        let sgir = (filter << 24) | (cpu_mask << 16) | irq;
        self.gicd_write32(GICD_SGIR, sgir);
        Ok(())
    }

    /// Acknowledges a pending interrupt and returns its ID.
    ///
    /// Returns `None` if no interrupt is pending (spurious interrupt).
    pub fn acknowledge(&self) -> Option<u32> {
        let iar = self.gicc_read32(GICC_IAR);
        let irq_id = iar & 0x3FF;
        if irq_id == 1023 { None } else { Some(irq_id) }
    }

    /// Signals End-of-Interrupt for the given IRQ.
    pub fn end_of_interrupt(&self, irq: u32) {
        self.gicc_write32(GICC_EOIR, irq & 0x3FF);
    }

    /// Returns the number of interrupt lines.
    pub fn num_irqs(&self) -> u32 {
        self.num_irqs
    }

    /// Returns the number of CPU interfaces.
    pub fn num_cpus(&self) -> u32 {
        self.num_cpus
    }

    fn check_irq(&self, irq: u32) -> Result<()> {
        if irq >= self.num_irqs {
            Err(Error::InvalidArgument)
        } else {
            Ok(())
        }
    }

    fn gicd_read32(&self, offset: usize) -> u32 {
        let addr = (self.gicd_base + offset) as *const u32;
        // SAFETY: gicd_base is a valid MMIO region for the GICv2 Distributor,
        // and offset is within the documented register map. Volatile read is required
        // to prevent the compiler from optimizing away hardware register accesses.
        unsafe { addr.read_volatile() }
    }

    fn gicd_write32(&self, offset: usize, val: u32) {
        let addr = (self.gicd_base + offset) as *mut u32;
        // SAFETY: gicd_base is a valid MMIO region for the GICv2 Distributor.
        // Volatile write ensures the hardware register is updated immediately.
        unsafe { addr.write_volatile(val) }
    }

    fn gicc_read32(&self, offset: usize) -> u32 {
        let addr = (self.gicc_base + offset) as *const u32;
        // SAFETY: gicc_base is a valid MMIO region for the GICv2 CPU Interface.
        // Volatile read prevents compiler from caching the hardware register value.
        unsafe { addr.read_volatile() }
    }

    fn gicc_write32(&self, offset: usize, val: u32) {
        let addr = (self.gicc_base + offset) as *mut u32;
        // SAFETY: gicc_base is a valid MMIO region for the GICv2 CPU Interface.
        // Volatile write ensures interrupt control signals are sent to hardware.
        unsafe { addr.write_volatile(val) }
    }
}

impl Default for ArmGicV2 {
    fn default() -> Self {
        Self::new(0, 0)
    }
}
