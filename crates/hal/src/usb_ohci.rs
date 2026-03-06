// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Open Host Controller Interface (OHCI) USB 1.1 host controller driver.
//!
//! Implements the OHCI specification for USB 1.1 full-speed (12 Mbps) and
//! low-speed (1.5 Mbps) host control. OHCI is the predecessor to EHCI and
//! typically used for legacy USB device support.
//!
//! # Register Layout
//!
//! All OHCI registers are accessed through a single contiguous MMIO region.
//! Unlike EHCI, there is no capability/operational split.
//!
//! # References
//!
//! - OpenHCI Open Host Controller Interface Specification for USB, Release 1.0a

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// OHCI HcControl register bits
const CTRL_CBSR_MASK: u32 = 0x3;
const CTRL_PLE: u32 = 1 << 2; // Periodic List Enable
const CTRL_IE: u32 = 1 << 3; // Isochronous Enable
const CTRL_CLE: u32 = 1 << 4; // Control List Enable
const CTRL_BLE: u32 = 1 << 5; // Bulk List Enable
const CTRL_HCFS_MASK: u32 = 0x3 << 6;
const CTRL_HCFS_RESET: u32 = 0x0 << 6;
const CTRL_HCFS_RESUME: u32 = 0x1 << 6;
const CTRL_HCFS_OPERATIONAL: u32 = 0x2 << 6;
const CTRL_HCFS_SUSPEND: u32 = 0x3 << 6;
const CTRL_IR: u32 = 1 << 8; // Interrupt Routing
const CTRL_RWC: u32 = 1 << 9; // Remote Wakeup Connected
const CTRL_RWE: u32 = 1 << 10; // Remote Wakeup Enable

// OHCI HcCommandStatus bits
const CMD_HCR: u32 = 1 << 0; // Host Controller Reset
const CMD_CLF: u32 = 1 << 1; // Control List Filled
const CMD_BLF: u32 = 1 << 2; // Bulk List Filled
const CMD_OCR: u32 = 1 << 3; // Ownership Change Request

// OHCI HcInterruptStatus / HcInterruptEnable bits
const INT_SO: u32 = 1 << 0; // Scheduling Overrun
const INT_WDH: u32 = 1 << 1; // Write Done Head
const INT_SF: u32 = 1 << 2; // Start of Frame
const INT_RD: u32 = 1 << 3; // Resume Detected
const INT_UE: u32 = 1 << 4; // Unrecoverable Error
const INT_FNO: u32 = 1 << 5; // Frame Number Overflow
const INT_RHSC: u32 = 1 << 6; // Root Hub Status Change
const INT_OC: u32 = 1 << 30; // Ownership Change
const INT_MIE: u32 = 1 << 31; // Master Interrupt Enable

// OHCI register offsets
const HC_REVISION: usize = 0x00;
const HC_CONTROL: usize = 0x04;
const HC_COMMAND_STATUS: usize = 0x08;
const HC_INTERRUPT_STATUS: usize = 0x0C;
const HC_INTERRUPT_ENABLE: usize = 0x10;
const HC_INTERRUPT_DISABLE: usize = 0x14;
const HC_HCCA: usize = 0x18;
const HC_PERIOD_CURRENT_ED: usize = 0x1C;
const HC_CONTROL_HEAD_ED: usize = 0x20;
const HC_CONTROL_CURRENT_ED: usize = 0x24;
const HC_BULK_HEAD_ED: usize = 0x28;
const HC_BULK_CURRENT_ED: usize = 0x2C;
const HC_DONE_HEAD: usize = 0x30;
const HC_FM_INTERVAL: usize = 0x34;
const HC_FM_REMAINING: usize = 0x38;
const HC_FM_NUMBER: usize = 0x3C;
const HC_PERIODIC_START: usize = 0x40;
const HC_LS_THRESHOLD: usize = 0x44;
const HC_RH_DESCRIPTOR_A: usize = 0x48;
const HC_RH_DESCRIPTOR_B: usize = 0x4C;
const HC_RH_STATUS: usize = 0x50;
const HC_RH_PORT_STATUS: usize = 0x54;

/// Maximum root hub ports for OHCI.
pub const OHCI_MAX_PORTS: usize = 15;

/// Default frame interval (1 ms = 11999 bit times + fit timing).
const DEFAULT_FM_INTERVAL: u32 = 0x2EDF;

/// Host Controller Communications Area (HCCA) size.
pub const HCCA_SIZE: usize = 256;

/// OHCI host controller driver.
pub struct OhciController {
    /// MMIO base address.
    base: usize,
    /// Number of downstream ports.
    num_ports: u8,
    /// Physical address of the HCCA.
    hcca_phys: u32,
    /// Whether the controller is initialized.
    initialized: bool,
}

impl OhciController {
    /// Creates a new OHCI controller instance.
    ///
    /// # Arguments
    ///
    /// * `mmio_base` - MMIO base address of the OHCI controller
    pub const fn new(mmio_base: usize) -> Self {
        Self {
            base: mmio_base,
            num_ports: 0,
            hcca_phys: 0,
            initialized: false,
        }
    }

    /// Initializes the OHCI controller.
    ///
    /// Takes ownership from BIOS (SMM), resets the controller, and configures it.
    ///
    /// # Arguments
    ///
    /// * `hcca_phys` - Physical address of the 256-byte HCCA (must be 256-byte aligned)
    pub fn init(&mut self, hcca_phys: u32) -> Result<()> {
        if hcca_phys & 0xFF != 0 {
            return Err(Error::InvalidArgument);
        }

        // Check if BIOS owns the controller (InterruptRouting bit)
        let ctrl = self.read32(HC_CONTROL);
        if ctrl & CTRL_IR != 0 {
            // Request ownership change from SMM
            self.write32(HC_COMMAND_STATUS, CMD_OCR);
            let mut timeout = 10_000u32;
            loop {
                if self.read32(HC_CONTROL) & CTRL_IR == 0 {
                    break;
                }
                if timeout == 0 {
                    return Err(Error::Busy);
                }
                timeout -= 1;
            }
        }

        // Assert HCReset
        self.write32(HC_COMMAND_STATUS, CMD_HCR);
        let mut timeout = 10_000u32;
        loop {
            if self.read32(HC_COMMAND_STATUS) & CMD_HCR == 0 {
                break;
            }
            if timeout == 0 {
                return Err(Error::Busy);
            }
            timeout -= 1;
        }

        // Set HCCA physical address
        self.hcca_phys = hcca_phys;
        self.write32(HC_HCCA, hcca_phys);

        // Configure frame interval
        self.write32(HC_FM_INTERVAL, DEFAULT_FM_INTERVAL | (0x2778 << 16));
        self.write32(HC_PERIODIC_START, (DEFAULT_FM_INTERVAL * 9) / 10);

        // Read number of downstream ports
        let rh_desc_a = self.read32(HC_RH_DESCRIPTOR_A);
        self.num_ports = (rh_desc_a & 0xFF) as u8;
        if self.num_ports as usize > OHCI_MAX_PORTS {
            return Err(Error::InvalidArgument);
        }

        // Set operational state
        let ctrl = self.read32(HC_CONTROL);
        let ctrl = (ctrl & !(CTRL_HCFS_MASK)) | CTRL_HCFS_OPERATIONAL;
        self.write32(HC_CONTROL, ctrl);

        // Enable interrupts
        self.write32(HC_INTERRUPT_ENABLE, INT_WDH | INT_RHSC | INT_UE | INT_MIE);

        self.initialized = true;
        Ok(())
    }

    /// Suspends the OHCI controller.
    pub fn suspend(&self) {
        let ctrl = self.read32(HC_CONTROL);
        let ctrl = (ctrl & !CTRL_HCFS_MASK) | CTRL_HCFS_SUSPEND;
        self.write32(HC_CONTROL, ctrl);
    }

    /// Resumes the OHCI controller from suspend.
    pub fn resume(&self) {
        let ctrl = self.read32(HC_CONTROL);
        let ctrl = (ctrl & !CTRL_HCFS_MASK) | CTRL_HCFS_RESUME;
        self.write32(HC_CONTROL, ctrl);
    }

    /// Reads and clears the interrupt status register.
    pub fn read_clear_interrupt_status(&self) -> u32 {
        let sts = self.read32(HC_INTERRUPT_STATUS);
        self.write32(HC_INTERRUPT_STATUS, sts);
        sts
    }

    /// Returns the port status register for a specific port.
    pub fn port_status(&self, port: u8) -> Result<u32> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        Ok(self.read32(HC_RH_PORT_STATUS + (port as usize * 4)))
    }

    /// Resets a downstream port.
    pub fn reset_port(&self, port: u8) -> Result<()> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        // Bit 4 of HcRhPortStatus: SetPortReset
        self.write32(HC_RH_PORT_STATUS + (port as usize * 4), 1 << 4);
        Ok(())
    }

    /// Returns the number of downstream ports.
    pub fn num_ports(&self) -> u8 {
        self.num_ports
    }

    /// Sets the Bulk List head ED pointer.
    pub fn set_bulk_head(&self, phys_ed: u32) {
        self.write32(HC_BULK_HEAD_ED, phys_ed);
        let cmd = self.read32(HC_COMMAND_STATUS);
        self.write32(HC_COMMAND_STATUS, cmd | CMD_BLF);
    }

    /// Sets the Control List head ED pointer.
    pub fn set_control_head(&self, phys_ed: u32) {
        self.write32(HC_CONTROL_HEAD_ED, phys_ed);
        let cmd = self.read32(HC_COMMAND_STATUS);
        self.write32(HC_COMMAND_STATUS, cmd | CMD_CLF);
    }

    fn read32(&self, offset: usize) -> u32 {
        let addr = (self.base + offset) as *const u32;
        // SAFETY: base is a valid OHCI MMIO region. All OHCI registers are 32-bit
        // aligned and accessible via volatile read.
        unsafe { addr.read_volatile() }
    }

    fn write32(&self, offset: usize, val: u32) {
        let addr = (self.base + offset) as *mut u32;
        // SAFETY: base is a valid OHCI MMIO region. Volatile write ensures
        // the controller receives commands immediately without compiler reordering.
        unsafe { addr.write_volatile(val) }
    }
}

impl Default for OhciController {
    fn default() -> Self {
        Self::new(0)
    }
}
