// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Enhanced Host Controller Interface (EHCI) USB 2.0 host controller driver.
//!
//! Implements the EHCI specification for USB 2.0 high-speed (480 Mbps) host control.
//! EHCI controllers appear as PCI devices and expose MMIO capability and operational registers.
//!
//! # Register Layout
//!
//! - **Capability Registers**: Base MMIO, read-only, describe controller capabilities
//! - **Operational Registers**: Base + CAPLENGTH offset, read/write, control operation
//!
//! # References
//!
//! - Enhanced Host Controller Interface Specification for Universal Serial Bus, Rev 1.0

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// Capability register offsets
const CAPLENGTH: usize = 0x00;
const HCIVERSION: usize = 0x02;
const HCSPARAMS: usize = 0x04;
const HCCPARAMS: usize = 0x08;
const HCSP_PORTROUTE: usize = 0x0C;

// Operational register offsets (from op_base = base + CAPLENGTH)
const USBCMD: usize = 0x00;
const USBSTS: usize = 0x04;
const USBINTR: usize = 0x08;
const FRINDEX: usize = 0x0C;
const CTRLDSSEGMENT: usize = 0x10;
const PERIODICLISTBASE: usize = 0x14;
const ASYNCLISTADDR: usize = 0x18;
const CONFIGFLAG: usize = 0x40;
const PORTSC_BASE: usize = 0x44;

// USBCMD bits
const CMD_RUN: u32 = 1 << 0;
const CMD_HCRESET: u32 = 1 << 1;
const CMD_FLS_MASK: u32 = 0x3 << 2;
const CMD_ASYNC_ENABLE: u32 = 1 << 5;
const CMD_PERIOD_ENABLE: u32 = 1 << 4;
const CMD_ASYNCDOORBELL: u32 = 1 << 6;

// USBSTS bits
const STS_HALTED: u32 = 1 << 12;
const STS_ASYNC_ADVANCE: u32 = 1 << 5;
const STS_PORT_CHANGE: u32 = 1 << 2;
const STS_USB_ERROR: u32 = 1 << 1;
const STS_USB_INTERRUPT: u32 = 1 << 0;

// PORTSC bits
const PORT_POWER: u32 = 1 << 12;
const PORT_RESET: u32 = 1 << 8;
const PORT_SUSPEND: u32 = 1 << 7;
const PORT_ENABLED: u32 = 1 << 2;
const PORT_CONNECT_STATUS_CHANGE: u32 = 1 << 1;
const PORT_CONNECT: u32 = 1 << 0;

/// Maximum number of root hub ports supported.
pub const EHCI_MAX_PORTS: usize = 15;

/// Reset timeout in microseconds.
const RESET_TIMEOUT_US: u32 = 250_000;

/// EHCI host controller driver.
pub struct EhciController {
    /// MMIO base address (capability registers start here).
    cap_base: usize,
    /// Operational registers base address (cap_base + CAPLENGTH).
    op_base: usize,
    /// Number of root hub ports.
    num_ports: u8,
    /// Whether 64-bit addressing is supported.
    is_64bit: bool,
    /// Whether the controller has been initialized.
    initialized: bool,
}

impl EhciController {
    /// Creates a new EHCI controller instance.
    ///
    /// # Arguments
    ///
    /// * `mmio_base` - Base MMIO address of the EHCI capability registers
    pub const fn new(mmio_base: usize) -> Self {
        Self {
            cap_base: mmio_base,
            op_base: 0,
            num_ports: 0,
            is_64bit: false,
            initialized: false,
        }
    }

    /// Initializes the EHCI controller.
    ///
    /// Reads capabilities, resets the controller, and configures it for operation.
    pub fn init(&mut self) -> Result<()> {
        // Read CAPLENGTH to find operational registers
        let caplength = self.cap_read8(CAPLENGTH);
        self.op_base = self.cap_base + caplength as usize;

        // Read HCSPARAMS for port count
        let hcsparams = self.cap_read32(HCSPARAMS);
        self.num_ports = (hcsparams & 0xF) as u8;
        if self.num_ports as usize > EHCI_MAX_PORTS {
            return Err(Error::InvalidArgument);
        }

        // Check 64-bit capability
        let hccparams = self.cap_read32(HCCPARAMS);
        self.is_64bit = hccparams & 1 != 0;

        // Halt the controller before reset
        self.op_write32(USBCMD, 0);
        let mut timeout = RESET_TIMEOUT_US;
        loop {
            if self.op_read32(USBSTS) & STS_HALTED != 0 {
                break;
            }
            if timeout == 0 {
                return Err(Error::Busy);
            }
            timeout -= 1;
        }

        // Issue HCRESET
        self.op_write32(USBCMD, CMD_HCRESET);
        timeout = RESET_TIMEOUT_US;
        loop {
            if self.op_read32(USBCMD) & CMD_HCRESET == 0 {
                break;
            }
            if timeout == 0 {
                return Err(Error::Busy);
            }
            timeout -= 1;
        }

        // Route all ports to EHCI (not companion controllers)
        self.op_write32(CONFIGFLAG, 1);

        // Power on all ports
        for i in 0..self.num_ports {
            let portsc = self.op_read32(PORTSC_BASE + (i as usize * 4));
            self.op_write32(PORTSC_BASE + (i as usize * 4), portsc | PORT_POWER);
        }

        self.initialized = true;
        Ok(())
    }

    /// Starts the host controller (sets Run/Stop bit).
    pub fn start(&self) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        let cmd = self.op_read32(USBCMD);
        self.op_write32(USBCMD, cmd | CMD_RUN);
        Ok(())
    }

    /// Stops the host controller.
    pub fn stop(&self) {
        let cmd = self.op_read32(USBCMD);
        self.op_write32(USBCMD, cmd & !CMD_RUN);
    }

    /// Returns the port status and control register for a port.
    pub fn port_status(&self, port: u8) -> Result<u32> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        Ok(self.op_read32(PORTSC_BASE + (port as usize * 4)))
    }

    /// Resets a root hub port.
    pub fn reset_port(&self, port: u8) -> Result<()> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        let offset = PORTSC_BASE + (port as usize * 4);
        let portsc = self.op_read32(offset);
        // Assert reset, clear Enable bit
        self.op_write32(offset, (portsc & !PORT_ENABLED) | PORT_RESET);
        Ok(())
    }

    /// Clears the reset signal on a port.
    pub fn clear_port_reset(&self, port: u8) -> Result<()> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        let offset = PORTSC_BASE + (port as usize * 4);
        let portsc = self.op_read32(offset);
        self.op_write32(offset, portsc & !PORT_RESET);
        Ok(())
    }

    /// Reads and clears the USB status register.
    pub fn read_clear_status(&self) -> u32 {
        let sts = self.op_read32(USBSTS);
        // Write-1-to-clear status bits
        self.op_write32(
            USBSTS,
            sts & (STS_ASYNC_ADVANCE | STS_PORT_CHANGE | STS_USB_ERROR | STS_USB_INTERRUPT),
        );
        sts
    }

    /// Enables specific interrupt sources.
    pub fn enable_interrupts(&self, mask: u32) {
        let cur = self.op_read32(USBINTR);
        self.op_write32(USBINTR, cur | mask);
    }

    /// Returns the number of root hub ports.
    pub fn num_ports(&self) -> u8 {
        self.num_ports
    }

    /// Returns whether 64-bit DMA addressing is supported.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    fn cap_read8(&self, offset: usize) -> u8 {
        let addr = (self.cap_base + offset) as *const u8;
        // SAFETY: cap_base is a valid EHCI capability MMIO region.
        // Volatile read is required for hardware register access.
        unsafe { addr.read_volatile() }
    }

    fn cap_read32(&self, offset: usize) -> u32 {
        let addr = (self.cap_base + offset) as *const u32;
        // SAFETY: cap_base is a valid EHCI capability MMIO region, and
        // all capability registers are 32-bit aligned.
        unsafe { addr.read_volatile() }
    }

    fn op_read32(&self, offset: usize) -> u32 {
        let addr = (self.op_base + offset) as *const u32;
        // SAFETY: op_base is the start of EHCI operational registers (cap_base + CAPLENGTH).
        // All operational registers are 32-bit aligned.
        unsafe { addr.read_volatile() }
    }

    fn op_write32(&self, offset: usize, val: u32) {
        let addr = (self.op_base + offset) as *mut u32;
        // SAFETY: op_base is the start of EHCI operational registers.
        // Volatile write ensures the controller receives the command immediately.
        unsafe { addr.write_volatile(val) }
    }
}

impl Default for EhciController {
    fn default() -> Self {
        Self::new(0)
    }
}
