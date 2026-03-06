// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB EHCI (Enhanced Host Controller Interface) driver.
//!
//! Implements USB 2.0 high-speed (480 Mbps) host controller support per the
//! EHCI specification. The controller uses a periodic and asynchronous
//! schedule for interrupt/isochronous and bulk/control transfers respectively.

use oncrix_lib::{Error, Result};

/// PCI class/subclass/programming interface for EHCI.
pub const EHCI_CLASS: u8 = 0x0C;
pub const EHCI_SUBCLASS: u8 = 0x03;
pub const EHCI_PROGIF: u8 = 0x20;

/// EHCI Capability Register offsets (read-only, relative to BAR0).
const CAP_CAPLENGTH: u32 = 0x00; // Capability registers length (1 byte)
const CAP_HCIVERSION: u32 = 0x02; // HCI version (2 bytes)
const CAP_HCSPARAMS: u32 = 0x04; // Host controller structural params
const CAP_HCCPARAMS: u32 = 0x08; // Host controller capability params

/// EHCI Operational Register offsets (relative to CAP_CAPLENGTH).
const OP_USBCMD: u32 = 0x00;
const OP_USBSTS: u32 = 0x04;
const OP_USBINTR: u32 = 0x08;
const OP_FRINDEX: u32 = 0x0C;
const OP_CTRLDSSEGMENT: u32 = 0x10;
const OP_PERIODICLISTBASE: u32 = 0x14;
const OP_ASYNCLISTADDR: u32 = 0x18;
const OP_CONFIGFLAG: u32 = 0x40;
const OP_PORTSC_BASE: u32 = 0x44; // PORTSC[0] — add 4*n for port n

/// USBCMD bits.
const CMD_RUN: u32 = 1 << 0;
const CMD_HCRESET: u32 = 1 << 1;
const CMD_FLS_1024: u32 = 0 << 2; // Periodic frame list size 1024
const CMD_FLS_512: u32 = 1 << 2;
const CMD_FLS_256: u32 = 2 << 2;
const CMD_PSE: u32 = 1 << 4; // Periodic schedule enable
const CMD_ASE: u32 = 1 << 5; // Asynchronous schedule enable
const CMD_IAAD: u32 = 1 << 6; // Interrupt on async advance doorbell
const CMD_ITC_1: u32 = 1 << 16; // Interrupt threshold: 1 micro-frame

/// USBSTS bits.
const STS_USBINT: u32 = 1 << 0;
const STS_USBERRINT: u32 = 1 << 1;
const STS_PORT_CHANGE: u32 = 1 << 2;
const STS_FLROLLOVER: u32 = 1 << 3;
const STS_HSERR: u32 = 1 << 4;
const STS_IAA: u32 = 1 << 5;
const STS_HCHALTED: u32 = 1 << 12;
const STS_RECLAMATION: u32 = 1 << 13;
const STS_PSS: u32 = 1 << 14;
const STS_ASS: u32 = 1 << 15;

/// USBINTR enable bits.
const INTR_USBINT: u32 = 1 << 0;
const INTR_USBERRINT: u32 = 1 << 1;
const INTR_PORT_CHANGE: u32 = 1 << 2;
const INTR_FLROLLOVER: u32 = 1 << 3;
const INTR_HSERR: u32 = 1 << 4;
const INTR_IAA: u32 = 1 << 5;

/// PORTSC bits.
const PORTSC_CONNECT: u32 = 1 << 0;
const PORTSC_CONNECT_CHG: u32 = 1 << 1;
const PORTSC_ENABLE: u32 = 1 << 2;
const PORTSC_ENABLE_CHG: u32 = 1 << 3;
const PORTSC_OVER_CURRENT: u32 = 1 << 4;
const PORTSC_OVER_CURRENT_CHG: u32 = 1 << 5;
const PORTSC_FORCE_RESUME: u32 = 1 << 6;
const PORTSC_SUSPEND: u32 = 1 << 7;
const PORTSC_RESET: u32 = 1 << 8;
const PORTSC_LS: u32 = 3 << 10; // Line status
const PORTSC_POWER: u32 = 1 << 12;
const PORTSC_OWNER: u32 = 1 << 13; // Port owner: 0=EHCI, 1=companion HC
const PORTSC_PIC: u32 = 3 << 14; // Port indicator control
const PORTSC_PTC: u32 = 0xF << 16; // Port test control
const PORTSC_WKCNNT_E: u32 = 1 << 20;

/// CONFIGFLAG bits.
const CF_CONFIGURED: u32 = 1 << 0;

/// Queue Head (QH) horizontal link pointer terminate bit.
const QH_T_BIT: u32 = 1 << 0;
/// Queue Head type bits.
const QH_TYPE_ITD: u32 = 0 << 1;
const QH_TYPE_QH: u32 = 1 << 1;
const QH_TYPE_SITD: u32 = 2 << 1;
const QH_TYPE_FSTN: u32 = 3 << 1;

/// Maximum number of ports supported.
const MAX_PORTS: usize = 15;

/// Queue Head in `#[repr(C)]` for DMA (must be 32-byte aligned in hardware).
#[repr(C, align(32))]
pub struct QueueHead {
    /// Horizontal link pointer.
    pub hlp: u32,
    /// Endpoint characteristics.
    pub ep_chars: u32,
    /// Endpoint capabilities.
    pub ep_caps: u32,
    /// Current qTD pointer.
    pub current_qtd: u32,
    // Overlay area (qTD transfer state).
    pub next_qtd: u32,
    pub alt_qtd: u32,
    pub token: u32,
    pub buf_ptr: [u32; 5],
    pub ext_buf_ptr: [u32; 5],
}

impl QueueHead {
    /// Create a zeroed Queue Head.
    pub const fn new() -> Self {
        Self {
            hlp: QH_T_BIT,
            ep_chars: 0,
            ep_caps: 0,
            current_qtd: QH_T_BIT,
            next_qtd: QH_T_BIT,
            alt_qtd: QH_T_BIT,
            token: 0,
            buf_ptr: [0u32; 5],
            ext_buf_ptr: [0u32; 5],
        }
    }
}

impl Default for QueueHead {
    fn default() -> Self {
        Self::new()
    }
}

/// Queue Transfer Descriptor in `#[repr(C)]` for DMA (must be 32-byte aligned).
#[repr(C, align(32))]
pub struct QtDescriptor {
    /// Next qTD pointer.
    pub next: u32,
    /// Alternate next qTD pointer.
    pub alt_next: u32,
    /// Transfer token (status, length, etc).
    pub token: u32,
    /// Buffer pointers (up to 5 pages).
    pub buf_ptr: [u32; 5],
    /// Extended buffer pointer high words.
    pub ext_buf_ptr: [u32; 5],
}

impl QtDescriptor {
    /// Create a zeroed qTD.
    pub const fn new() -> Self {
        Self {
            next: QH_T_BIT,
            alt_next: QH_T_BIT,
            token: 0,
            buf_ptr: [0u32; 5],
            ext_buf_ptr: [0u32; 5],
        }
    }
}

impl Default for QtDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

/// USB port state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortState {
    /// No device connected.
    Empty,
    /// Low-speed device (will be handed to companion HC).
    LowSpeed,
    /// Full-speed device (will be handed to companion HC).
    FullSpeed,
    /// High-speed USB 2.0 device.
    HighSpeed,
    /// Port suspended.
    Suspended,
}

/// EHCI host controller driver.
pub struct EhciHcd {
    /// Virtual address of the MMIO region (BAR0).
    cap_base: usize,
    /// Virtual address of the operational registers.
    op_base: usize,
    /// Number of root hub ports.
    num_ports: usize,
    /// Controller is running.
    running: bool,
    /// Per-port connection state.
    port_state: [PortState; MAX_PORTS],
}

impl EhciHcd {
    /// Create a new EHCI driver.
    ///
    /// # Arguments
    /// - `mmio_base`: virtual address of the EHCI MMIO region (BAR0)
    pub fn new(mmio_base: usize) -> Self {
        Self {
            cap_base: mmio_base,
            op_base: 0, // Computed during init().
            num_ports: 0,
            running: false,
            port_state: [PortState::Empty; MAX_PORTS],
        }
    }

    /// Initialize the EHCI controller.
    pub fn init(&mut self) -> Result<()> {
        // Read the capability registers length to find the operational base.
        let cap_len = self.read_cap8(CAP_CAPLENGTH) as usize;
        self.op_base = self.cap_base + cap_len;
        // Parse HCSPARAMS for the number of ports.
        let hcsparams = self.read_cap32(CAP_HCSPARAMS);
        self.num_ports = (hcsparams & 0x0F) as usize;
        if self.num_ports > MAX_PORTS {
            self.num_ports = MAX_PORTS;
        }
        // Stop the controller and reset.
        self.stop()?;
        self.reset()?;
        // Configure for full use.
        self.write_op32(OP_CTRLDSSEGMENT, 0); // 32-bit mode.
        self.write_op32(
            OP_USBINTR,
            INTR_USBINT | INTR_USBERRINT | INTR_PORT_CHANGE | INTR_IAA,
        );
        self.write_op32(OP_USBCMD, CMD_RUN | CMD_ITC_1);
        // Route all ports to EHCI.
        self.write_op32(OP_CONFIGFLAG, CF_CONFIGURED);
        // Power up all ports.
        for i in 0..self.num_ports {
            let portsc = self.read_portsc(i);
            self.write_portsc(i, portsc | PORTSC_POWER);
        }
        self.running = true;
        Ok(())
    }

    /// Stop the EHCI controller.
    pub fn stop(&mut self) -> Result<()> {
        let cmd = self.read_op32(OP_USBCMD);
        self.write_op32(OP_USBCMD, cmd & !CMD_RUN);
        let mut tries = 0u32;
        loop {
            if (self.read_op32(OP_USBSTS) & STS_HCHALTED) != 0 {
                self.running = false;
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Reset the controller (must be halted first).
    fn reset(&mut self) -> Result<()> {
        self.write_op32(OP_USBCMD, CMD_HCRESET);
        let mut tries = 0u32;
        loop {
            if (self.read_op32(OP_USBCMD) & CMD_HCRESET) == 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Reset a specific root hub port.
    pub fn reset_port(&mut self, port: usize) -> Result<()> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        let portsc = self.read_portsc(port);
        // Disable port enable before reset.
        self.write_portsc(port, (portsc & !PORTSC_ENABLE) | PORTSC_RESET);
        // Hold reset for at least 50 ms (simulated via spin here).
        for _ in 0..500_000 {
            core::hint::spin_loop();
        }
        // Release reset.
        let portsc = self.read_portsc(port);
        self.write_portsc(port, portsc & !PORTSC_RESET);
        // Wait for reset to complete.
        let mut tries = 0u32;
        loop {
            if (self.read_portsc(port) & PORTSC_RESET) == 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Handle an EHCI interrupt; returns USBSTS value.
    pub fn handle_interrupt(&mut self) -> u32 {
        let sts = self.read_op32(OP_USBSTS);
        // Write-to-clear all status bits.
        self.write_op32(OP_USBSTS, sts & 0x3F);
        if (sts & STS_PORT_CHANGE) != 0 {
            self.scan_ports();
        }
        sts
    }

    /// Scan all root hub ports and update their cached state.
    fn scan_ports(&mut self) {
        for i in 0..self.num_ports {
            let portsc = self.read_portsc(i);
            if (portsc & PORTSC_CONNECT) == 0 {
                self.port_state[i] = PortState::Empty;
            } else if (portsc & PORTSC_ENABLE) != 0 {
                // High-speed: EHCI handles it.
                self.port_state[i] = PortState::HighSpeed;
            } else {
                // Low/full speed: hand to companion HC.
                let ls = (portsc >> 10) & 0x3;
                self.port_state[i] = if ls == 1 {
                    PortState::LowSpeed
                } else {
                    PortState::FullSpeed
                };
                // Release to companion HC.
                self.write_portsc(i, portsc | PORTSC_OWNER);
            }
            // Clear change bits.
            self.write_portsc(i, portsc | PORTSC_CONNECT_CHG | PORTSC_ENABLE_CHG);
        }
    }

    /// Return the state of a specific port.
    pub fn port_state(&self, port: usize) -> Option<PortState> {
        if port < self.num_ports {
            Some(self.port_state[port])
        } else {
            None
        }
    }

    /// Return the number of root hub ports.
    pub fn num_ports(&self) -> usize {
        self.num_ports
    }

    // --- Register access helpers ---

    fn read_cap8(&self, offset: u32) -> u8 {
        let addr = (self.cap_base + offset as usize) as *const u8;
        // SAFETY: cap_base is the BAR0 EHCI MMIO region; CAP offsets are within
        // the 16-byte capability header defined by the EHCI specification.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn read_cap32(&self, offset: u32) -> u32 {
        let addr = (self.cap_base + offset as usize) as *const u32;
        // SAFETY: Same MMIO region; 4-byte aligned capability registers.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn read_op32(&self, offset: u32) -> u32 {
        let addr = (self.op_base + offset as usize) as *const u32;
        // SAFETY: op_base = cap_base + cap_len; all OP offsets are within
        // the EHCI operational register space (256 bytes + 4*n for ports).
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write_op32(&mut self, offset: u32, val: u32) {
        let addr = (self.op_base + offset as usize) as *mut u32;
        // SAFETY: Volatile write to a hardware register in the EHCI MMIO region.
        unsafe { core::ptr::write_volatile(addr, val) }
    }

    fn read_portsc(&self, port: usize) -> u32 {
        self.read_op32(OP_PORTSC_BASE + (port as u32) * 4)
    }

    fn write_portsc(&mut self, port: usize, val: u32) {
        self.write_op32(OP_PORTSC_BASE + (port as u32) * 4, val);
    }
}
