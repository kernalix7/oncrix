// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB UHCI (Universal Host Controller Interface) driver.
//!
//! Implements USB 1.1 full-speed (12 Mbps) and low-speed (1.5 Mbps) host
//! controller support per the UHCI specification. UHCI is a PIO-based
//! controller using a frame list and a linked list of Transfer Descriptors.

use oncrix_lib::{Error, Result};

/// PCI class/subclass/programming interface for UHCI.
pub const UHCI_CLASS: u8 = 0x0C;
pub const UHCI_SUBCLASS: u8 = 0x03;
pub const UHCI_PROGIF: u8 = 0x00;

/// UHCI I/O register offsets (relative to the PCI BAR4 I/O base).
const REG_USBCMD: u16 = 0x00;
const REG_USBSTS: u16 = 0x02;
const REG_USBINTR: u16 = 0x04;
const REG_FRNUM: u16 = 0x06;
const REG_FRBASEADDR: u16 = 0x08;
const REG_SOFMOD: u16 = 0x0C;
const REG_PORTSC1: u16 = 0x10;
const REG_PORTSC2: u16 = 0x12;

/// USBCMD bits.
const CMD_RUN: u16 = 1 << 0;
const CMD_HCRESET: u16 = 1 << 1;
const CMD_GRESET: u16 = 1 << 2;
const CMD_EGSM: u16 = 1 << 3; // Enter global suspend
const CMD_FGR: u16 = 1 << 4; // Force global resume
const CMD_SWDBG: u16 = 1 << 5; // SW debug
const CMD_CF: u16 = 1 << 6; // Configure flag
const CMD_MAXP: u16 = 1 << 7; // Max packet size (0=32, 1=64)

/// USBSTS bits.
const STS_USBINT: u16 = 1 << 0;
const STS_ERROR: u16 = 1 << 1;
const STS_RESUME: u16 = 1 << 2;
const STS_HSE: u16 = 1 << 3; // Host system error
const STS_HCPE: u16 = 1 << 4; // Host controller process error
const STS_HALTED: u16 = 1 << 5;

/// USBINTR bits.
const INTR_TIMEOUT_CRC: u16 = 1 << 0;
const INTR_RESUME: u16 = 1 << 1;
const INTR_IOC: u16 = 1 << 2;
const INTR_SP: u16 = 1 << 3; // Short packet

/// PORTSC bits.
const PORTSC_CONNECT: u16 = 1 << 0;
const PORTSC_CONNECT_CHG: u16 = 1 << 1;
const PORTSC_ENABLE: u16 = 1 << 2;
const PORTSC_ENABLE_CHG: u16 = 1 << 3;
const PORTSC_LINE_STATUS: u16 = 3 << 4;
const PORTSC_RESUME_DETECT: u16 = 1 << 6;
const PORTSC_LOW_SPEED: u16 = 1 << 8;
const PORTSC_RESET: u16 = 1 << 9;
const PORTSC_SUSPEND: u16 = 1 << 12;

/// Frame List size in entries (1024 × 4 bytes = 4 KiB).
const FRAME_LIST_SIZE: usize = 1024;

/// Frame list entry terminate bit.
const FL_TERMINATE: u32 = 1 << 0;

/// Transfer Descriptor (TD) in `#[repr(C)]` for DMA (16-byte aligned).
#[repr(C, align(16))]
pub struct TransferDesc {
    /// Link pointer (next TD or QH, with LP_TERMINATE/LP_QH bits).
    pub link: u32,
    /// Control and status.
    pub status: u32,
    /// Token (device address, endpoint, data direction, max length).
    pub token: u32,
    /// Buffer pointer (physical address of data).
    pub buf_ptr: u32,
}

/// TD link pointer bits.
const LP_TERMINATE: u32 = 1 << 0;
const LP_QH: u32 = 1 << 1; // Next is a QH
const LP_DEPTH: u32 = 1 << 2; // Breadth=0, Depth=1

/// TD status bits.
const TD_STATUS_ACTIVE: u32 = 1 << 23;
const TD_STATUS_STALLED: u32 = 1 << 22;
const TD_STATUS_DATA_BUF_ERR: u32 = 1 << 21;
const TD_STATUS_BABBLE: u32 = 1 << 20;
const TD_STATUS_NAK: u32 = 1 << 19;
const TD_STATUS_CRC_TIMEOUT: u32 = 1 << 18;
const TD_STATUS_BITSTUFF: u32 = 1 << 17;
const TD_STATUS_SPD: u32 = 1 << 29; // Short packet detect
const TD_STATUS_IOC: u32 = 1 << 24; // Interrupt on complete
const TD_STATUS_ISO: u32 = 1 << 25; // Isochronous
const TD_STATUS_LOW_SPEED: u32 = 1 << 26;
const TD_STATUS_ERROR_MASK: u32 = 3 << 27; // Error counter (2 bits)

impl TransferDesc {
    /// Create a zeroed, terminated TD.
    pub const fn new() -> Self {
        Self {
            link: LP_TERMINATE,
            status: 0,
            token: 0,
            buf_ptr: 0,
        }
    }
}

impl Default for TransferDesc {
    fn default() -> Self {
        Self::new()
    }
}

/// Queue Head (QH) in `#[repr(C)]` for DMA (16-byte aligned).
#[repr(C, align(16))]
pub struct QueueHead {
    /// Horizontal link pointer (next QH or terminate).
    pub hlp: u32,
    /// Element link pointer (first TD in this QH).
    pub elp: u32,
}

const QH_TERMINATE: u32 = 1 << 0;
const QH_IS_QH: u32 = 1 << 1;

impl QueueHead {
    /// Create a zeroed, terminated QH.
    pub const fn new() -> Self {
        Self {
            hlp: QH_TERMINATE,
            elp: QH_TERMINATE,
        }
    }
}

impl Default for QueueHead {
    fn default() -> Self {
        Self::new()
    }
}

/// UHCI host controller driver.
pub struct UhciHcd {
    /// Base PIO port from PCI BAR4.
    io_base: u16,
    /// Number of root hub ports (typically 2).
    num_ports: usize,
    /// Controller is running.
    running: bool,
}

impl UhciHcd {
    /// Create a new UHCI driver.
    ///
    /// # Arguments
    /// - `io_base`: base PIO port from PCI BAR4
    pub fn new(io_base: u16) -> Self {
        Self {
            io_base,
            num_ports: 2,
            running: false,
        }
    }

    /// Initialize the UHCI controller.
    pub fn init(&mut self) -> Result<()> {
        self.global_reset()?;
        self.hc_reset()?;
        // Set SOF timing (default 64 = 1 ms frame period).
        self.write8(REG_SOFMOD, 64);
        // Enable interrupts.
        self.write16(REG_USBINTR, INTR_IOC | INTR_RESUME | INTR_TIMEOUT_CRC);
        // Run.
        self.write16(REG_USBCMD, CMD_RUN | CMD_MAXP | CMD_CF);
        self.running = true;
        Ok(())
    }

    /// Perform a global USB reset (resets all downstream devices).
    fn global_reset(&mut self) -> Result<()> {
        self.write16(REG_USBCMD, CMD_GRESET);
        for _ in 0..100_000 {
            core::hint::spin_loop();
        }
        self.write16(REG_USBCMD, 0);
        Ok(())
    }

    /// Reset the host controller.
    fn hc_reset(&mut self) -> Result<()> {
        self.write16(REG_USBCMD, CMD_HCRESET);
        let mut tries = 0u32;
        loop {
            if (self.read16(REG_USBCMD) & CMD_HCRESET) == 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Reset a root hub port.
    pub fn reset_port(&mut self, port: usize) -> Result<()> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        let reg = if port == 0 { REG_PORTSC1 } else { REG_PORTSC2 };
        // Assert reset.
        self.write16(reg, PORTSC_RESET);
        for _ in 0..100_000 {
            core::hint::spin_loop();
        }
        // Release reset.
        self.write16(reg, 0);
        for _ in 0..50_000 {
            core::hint::spin_loop();
        }
        // Enable the port.
        self.write16(reg, PORTSC_ENABLE);
        Ok(())
    }

    /// Handle a UHCI interrupt; returns the USBSTS value.
    pub fn handle_interrupt(&mut self) -> u16 {
        let sts = self.read16(REG_USBSTS);
        // Write-to-clear.
        self.write16(REG_USBSTS, sts & 0x3F);
        sts
    }

    /// Check if a device is connected on the given port.
    pub fn is_device_connected(&self, port: usize) -> bool {
        if port >= self.num_ports {
            return false;
        }
        let reg = if port == 0 { REG_PORTSC1 } else { REG_PORTSC2 };
        (self.read16(reg) & PORTSC_CONNECT) != 0
    }

    /// Check if device on port is low-speed.
    pub fn is_low_speed(&self, port: usize) -> bool {
        if port >= self.num_ports {
            return false;
        }
        let reg = if port == 0 { REG_PORTSC1 } else { REG_PORTSC2 };
        (self.read16(reg) & PORTSC_LOW_SPEED) != 0
    }

    // --- PIO helpers ---

    fn read8(&self, offset: u16) -> u8 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u8;
            // SAFETY: io_base is a valid PCI BAR4 I/O port for UHCI;
            // REG_* offsets are within the 20-byte UHCI register space.
            unsafe {
                core::arch::asm!(
                    "in al, dx",
                    in("dx") self.io_base + offset,
                    out("al") val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
        #[allow(unreachable_code)]
        0
    }

    fn read16(&self, offset: u16) -> u16 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u16;
            // SAFETY: io_base is a valid PCI BAR4 I/O port; 2-byte aligned register.
            unsafe {
                core::arch::asm!(
                    "in ax, dx",
                    in("dx") self.io_base + offset,
                    out("ax") val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
        #[allow(unreachable_code)]
        0
    }

    fn write8(&mut self, offset: u16, val: u8) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: Volatile PIO write to a UHCI register.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") self.io_base + offset,
                in("al") val,
                options(nomem, nostack)
            );
        }
    }

    fn write16(&mut self, offset: u16, val: u16) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: Volatile PIO write to a 2-byte aligned UHCI register.
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") self.io_base + offset,
                in("ax") val,
                options(nomem, nostack)
            );
        }
    }
}
