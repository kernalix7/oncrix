// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! USB EHCI (Enhanced Host Controller Interface) driver.
//!
//! EHCI provides USB 2.0 (High Speed, 480 Mbps) host controller functionality.
//! It uses two schedule lists:
//! - **Asynchronous schedule**: For Control and Bulk transfers (linked QH list).
//! - **Periodic schedule**: For Interrupt and Isochronous transfers (frame list).
//!
//! # Initialization sequence
//! 1. Read Capability Registers (CAPLENGTH, HCIVERSION, HCSPARAMS, HCCPARAMS).
//! 2. Reset the host controller (USBCMD.HCRESET).
//! 3. Set CTRLDSSEGMENT, configure PERIODICLISTBASE and ASYNCLISTADDR.
//! 4. Set USBCMD.RS (Run/Stop) to start.
//! 5. Route ports to EHCI (CONFIGFLAG = 1).
//!
//! Reference: Enhanced Host Controller Interface Specification for USB (EHCI) r1.0.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Capability Register Offsets
// ---------------------------------------------------------------------------

/// Capability Length: byte offset to Operational Registers.
pub const CAP_CAPLENGTH: u32 = 0x00;
/// HC Interface Version Number (BCD, upper 16 bits of the same word as CAPLENGTH).
pub const CAP_HCIVERSION: u32 = 0x02;
/// Structural Parameters: number of ports, companion controllers, etc.
pub const CAP_HCSPARAMS: u32 = 0x04;
/// Capability Parameters: 64-bit addressing, programmable frame list, etc.
pub const CAP_HCCPARAMS: u32 = 0x08;

// ---------------------------------------------------------------------------
// Operational Register Offsets (relative to CAPLENGTH base)
// ---------------------------------------------------------------------------

/// USBCMD: USB Command.
pub const OPS_USBCMD: u32 = 0x00;
/// USBSTS: USB Status.
pub const OPS_USBSTS: u32 = 0x04;
/// USBINTR: USB Interrupt Enable.
pub const OPS_USBINTR: u32 = 0x08;
/// FRINDEX: USB Frame Index.
pub const OPS_FRINDEX: u32 = 0x0C;
/// CTRLDSSEGMENT: 4-Gigabyte Segment Selector for 64-bit addressing.
pub const OPS_CTRLDSSEGSMENT: u32 = 0x10;
/// PERIODICLISTBASE: Frame List Base Address.
pub const OPS_PERIODICLISTBASE: u32 = 0x14;
/// ASYNCLISTADDR: Next Asynchronous List Address.
pub const OPS_ASYNCLISTADDR: u32 = 0x18;
/// CONFIGFLAG: Configured Flag Register.
pub const OPS_CONFIGFLAG: u32 = 0x40;
/// PORTSC base offset (per-port, 4 bytes each starting here).
pub const OPS_PORTSC_BASE: u32 = 0x44;

// ---------------------------------------------------------------------------
// USBCMD Bits
// ---------------------------------------------------------------------------

/// USBCMD: Run/Stop.
pub const CMD_RS: u32 = 1 << 0;
/// USBCMD: Host Controller Reset.
pub const CMD_HCRESET: u32 = 1 << 1;
/// USBCMD: Frame List Size (bits 3:2; 00 = 1024 frames).
pub const CMD_FLS_1024: u32 = 0 << 2;
/// USBCMD: Periodic Schedule Enable.
pub const CMD_PSE: u32 = 1 << 4;
/// USBCMD: Asynchronous Schedule Enable.
pub const CMD_ASE: u32 = 1 << 5;
/// USBCMD: Interrupt Advance Doorbell.
pub const CMD_IAAD: u32 = 1 << 6;
/// USBCMD: Asynchronous Schedule Park Mode Enable.
pub const _CMD_ASPE: u32 = 1 << 11;

// ---------------------------------------------------------------------------
// USBSTS / USBINTR Bits
// ---------------------------------------------------------------------------

/// Status/Interrupt: USB Interrupt (transaction complete).
pub const STS_USBINT: u32 = 1 << 0;
/// Status/Interrupt: USB Error Interrupt.
pub const STS_USBERRINT: u32 = 1 << 1;
/// Status/Interrupt: Port Change Detect.
pub const STS_PCD: u32 = 1 << 2;
/// Status/Interrupt: Frame List Rollover.
pub const _STS_FLR: u32 = 1 << 3;
/// Status/Interrupt: Host System Error.
pub const STS_HSE: u32 = 1 << 4;
/// Status/Interrupt: Interrupt on Async Advance.
pub const STS_IAA: u32 = 1 << 5;
/// Status: HC Halted (RS=0, all transactions stopped).
pub const STS_HCHALTED: u32 = 1 << 12;

// ---------------------------------------------------------------------------
// PORTSC Bits
// ---------------------------------------------------------------------------

/// PORTSC: Current Connect Status.
pub const PORT_CCS: u32 = 1 << 0;
/// PORTSC: Connect Status Change (write 1 to clear).
pub const PORT_CSC: u32 = 1 << 1;
/// PORTSC: Port Enabled/Disabled.
pub const PORT_PE: u32 = 1 << 2;
/// PORTSC: Port Enable/Disable Change.
pub const PORT_PEC: u32 = 1 << 3;
/// PORTSC: Over-current Active.
pub const _PORT_OCA: u32 = 1 << 4;
/// PORTSC: Port Reset.
pub const PORT_RESET: u32 = 1 << 8;
/// PORTSC: Line Status (bits 11:10; 01 = K-state = low-speed device).
pub const PORT_LS_MASK: u32 = 3 << 10;
/// PORTSC: Port Power.
pub const PORT_PP: u32 = 1 << 12;
/// PORTSC: Port Owner (1 = companion HC owns this port).
pub const PORT_OWNER: u32 = 1 << 13;
/// PORTSC: Port Speed: 0 = FS/LS, 1 = HS (bit not valid on all controllers).
const _PORT_SPEED: u32 = 1 << 26;

// ---------------------------------------------------------------------------
// Transfer Descriptor (qTD)
// ---------------------------------------------------------------------------

/// EHCI queue Transfer Descriptor.
///
/// `#[repr(C)]` required for DMA layout.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TransferDescriptor {
    /// Horizontal link pointer to next qTD (or terminate bit 0).
    pub next_qtd: u32,
    /// Alternate next qTD (for short packet handling).
    pub alt_next_qtd: u32,
    /// Token: status, PID, CERR, C_Page, IOC, TotalBytesToTransfer, dt.
    pub token: u32,
    /// Buffer page pointers (5 entries; entry 0 also has offset in bits 11:0).
    pub buf_ptr: [u32; 5],
    /// High 32 bits of buffer page pointers (for 64-bit addressing).
    pub buf_ptr_hi: [u32; 5],
}

impl Default for TransferDescriptor {
    fn default() -> Self {
        Self {
            next_qtd: 1,     // Terminate
            alt_next_qtd: 1, // Terminate
            token: 0,
            buf_ptr: [0u32; 5],
            buf_ptr_hi: [0u32; 5],
        }
    }
}

/// qTD token: Active bit.
pub const QTD_TOKEN_ACTIVE: u32 = 1 << 7;
/// qTD token: Halted bit.
pub const QTD_TOKEN_HALTED: u32 = 1 << 6;
/// qTD token: Data Buffer Error.
pub const QTD_TOKEN_DBE: u32 = 1 << 5;
/// qTD token: Babble Detected.
pub const QTD_TOKEN_BABBLE: u32 = 1 << 4;
/// qTD token: Transaction Error.
pub const QTD_TOKEN_XACT_ERR: u32 = 1 << 3;
/// qTD token: Missed Micro-frame.
pub const _QTD_TOKEN_MMF: u32 = 1 << 2;
/// qTD token: Interrupt On Complete.
pub const QTD_TOKEN_IOC: u32 = 1 << 15;
/// qTD token: Data Toggle.
pub const QTD_TOKEN_DT: u32 = 1 << 31;
/// qTD token: Total bytes to transfer shift (bits 30:16).
pub const QTD_TOKEN_BYTES_SHIFT: u32 = 16;
/// qTD token: CERR field shift (bits 11:10).
pub const QTD_TOKEN_CERR_SHIFT: u32 = 10;
/// qTD token: PID Code shift (bits 9:8). 0=OUT, 1=IN, 2=SETUP.
pub const QTD_TOKEN_PID_SHIFT: u32 = 8;

// ---------------------------------------------------------------------------
// Queue Head (QH)
// ---------------------------------------------------------------------------

/// EHCI Queue Head.
///
/// `#[repr(C)]` required for DMA.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct QueueHead {
    /// Horizontal Link Pointer (to next QH or iTD in the schedule).
    pub hlp: u32,
    /// Endpoint characteristics: device address, endpoint number, speed, max packet size.
    pub ep_char: u32,
    /// Endpoint capabilities: interrupt scheduling mask, split transaction params.
    pub ep_cap: u32,
    /// Current qTD Pointer.
    pub current_qtd: u32,
    /// Overlay: next qTD pointer.
    pub next_qtd: u32,
    /// Overlay: alternate next qTD pointer.
    pub alt_next_qtd: u32,
    /// Overlay: token.
    pub token: u32,
    /// Overlay: buffer page pointers.
    pub buf_ptr: [u32; 5],
    /// Overlay: high 32 bits of buffer pointers.
    pub buf_ptr_hi: [u32; 5],
}

impl Default for QueueHead {
    fn default() -> Self {
        Self {
            hlp: 1, // Terminate
            ep_char: 0,
            ep_cap: 0,
            current_qtd: 0,
            next_qtd: 1,     // Terminate
            alt_next_qtd: 1, // Terminate
            token: 0,
            buf_ptr: [0u32; 5],
            buf_ptr_hi: [0u32; 5],
        }
    }
}

/// QH HLP Terminate bit.
pub const QH_HLP_T: u32 = 1 << 0;
/// QH EP char: device address mask.
pub const QH_EPCHAR_DEV_MASK: u32 = 0x7F;
/// QH EP char: endpoint number shift (bits 11:8).
pub const QH_EPCHAR_ENDPT_SHIFT: u32 = 8;
/// QH EP char: speed (bits 13:12; 10 = High Speed).
pub const QH_EPCHAR_HS: u32 = 2 << 12;
/// QH EP char: data toggle control from qTD.
pub const QH_EPCHAR_DTC: u32 = 1 << 14;
/// QH EP char: Head of Reclamation List (mark the dummy head QH).
pub const QH_EPCHAR_H: u32 = 1 << 15;
/// QH EP char: max packet size shift (bits 26:16).
pub const QH_EPCHAR_MAXPKT_SHIFT: u32 = 16;

// ---------------------------------------------------------------------------
// USB Speed Detection
// ---------------------------------------------------------------------------

/// USB device speed detected from PORTSC line status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsbSpeed {
    /// Low speed (1.5 Mbps).
    Low,
    /// Full speed (12 Mbps).
    Full,
    /// High speed (480 Mbps) — managed by EHCI.
    High,
}

// ---------------------------------------------------------------------------
// MMIO Helpers
// ---------------------------------------------------------------------------

/// Reads a 32-bit MMIO register.
///
/// # Safety
/// `base + offset` must be a valid mapped EHCI register address.
#[inline]
unsafe fn read32(base: u64, offset: u32) -> u32 {
    let ptr = (base + offset as u64) as *const u32;
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Writes a 32-bit MMIO register.
///
/// # Safety
/// See `read32`.
#[inline]
unsafe fn write32(base: u64, offset: u32, val: u32) {
    let ptr = (base + offset as u64) as *mut u32;
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

// ---------------------------------------------------------------------------
// EHCI Controller
// ---------------------------------------------------------------------------

/// EHCI host controller driver.
pub struct EhciController {
    /// Virtual base address of the Capability Registers.
    cap_base: u64,
    /// Virtual base address of the Operational Registers (cap_base + CAPLENGTH).
    ops_base: u64,
    /// Number of ports on this host controller.
    num_ports: u8,
}

impl EhciController {
    /// Creates a new `EhciController` at `cap_base`.
    ///
    /// Reads CAPLENGTH to locate Operational Registers and HCSPARAMS for port count.
    ///
    /// # Safety
    /// `cap_base` must be the virtual address of the mapped EHCI BAR.
    pub unsafe fn new(cap_base: u64) -> Self {
        // SAFETY: Reading CAPLENGTH and HCSPARAMS from the Capability Register space.
        unsafe {
            let cap_len = (read32(cap_base, CAP_CAPLENGTH) & 0xFF) as u64;
            let ops_base = cap_base + cap_len;
            let hcsparams = read32(cap_base, CAP_HCSPARAMS);
            let num_ports = (hcsparams & 0x0F) as u8;
            Self {
                cap_base,
                ops_base,
                num_ports,
            }
        }
    }

    /// Resets the host controller.
    ///
    /// Clears RS, then sets HCRESET and waits for it to clear.
    ///
    /// # Safety
    /// No USB transactions should be in progress during reset.
    pub unsafe fn reset(&self) -> Result<()> {
        // SAFETY: HC reset sequence per EHCI spec §4.2.2.
        unsafe {
            // Stop the HC
            let cmd = read32(self.ops_base, OPS_USBCMD);
            write32(self.ops_base, OPS_USBCMD, cmd & !CMD_RS);
            let mut spin = 100_000u32;
            while read32(self.ops_base, OPS_USBSTS) & STS_HCHALTED == 0 {
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }
            // Issue HC reset
            write32(self.ops_base, OPS_USBCMD, CMD_HCRESET);
            spin = 100_000;
            while read32(self.ops_base, OPS_USBCMD) & CMD_HCRESET != 0 {
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }
        }
        Ok(())
    }

    /// Initializes EHCI: sets frame list, async list, clears segment, sets CONFIGFLAG.
    ///
    /// # Parameters
    /// - `frame_list_phys`: Physical address of the 1024-entry periodic frame list.
    /// - `async_list_phys`: Physical address of the dummy head Queue Head.
    ///
    /// # Safety
    /// Both physical addresses must be valid DMA-accessible memory with correct alignment.
    pub unsafe fn init(&self, frame_list_phys: u64, async_list_phys: u64) -> Result<()> {
        // SAFETY: EHCI initialization sequence per spec §4.2.
        unsafe {
            // Set segment register to 0 for 32-bit DMA
            write32(self.ops_base, OPS_CTRLDSSEGSMENT, 0);

            // Program frame list and async list base
            write32(self.ops_base, OPS_PERIODICLISTBASE, frame_list_phys as u32);
            write32(self.ops_base, OPS_ASYNCLISTADDR, async_list_phys as u32);

            // Enable periodic and async schedules, start HC
            let cmd = CMD_RS | CMD_PSE | CMD_ASE | CMD_FLS_1024;
            write32(self.ops_base, OPS_USBCMD, cmd);

            // Wait for HC to start
            let mut spin = 100_000u32;
            while read32(self.ops_base, OPS_USBSTS) & STS_HCHALTED != 0 {
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }

            // Route all ports to EHCI (instead of companion controllers)
            write32(self.ops_base, OPS_CONFIGFLAG, 1);

            // Enable interrupts
            write32(
                self.ops_base,
                OPS_USBINTR,
                STS_USBINT | STS_USBERRINT | STS_PCD | STS_IAA,
            );
        }
        Ok(())
    }

    /// Returns the number of root hub ports.
    pub fn num_ports(&self) -> u8 {
        self.num_ports
    }

    /// Reads the PORTSC register for port `port` (0-indexed).
    ///
    /// # Safety
    /// `port` must be < `num_ports`.
    pub unsafe fn port_status(&self, port: u8) -> Result<u32> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: Accessing a valid port register.
        Ok(unsafe { read32(self.ops_base, OPS_PORTSC_BASE + (port as u32) * 4) })
    }

    /// Detects the speed of the device attached to `port`.
    ///
    /// # Safety
    /// `port` must be < `num_ports` and a device must be connected.
    pub unsafe fn detect_speed(&self, port: u8) -> Result<UsbSpeed> {
        // SAFETY: port_status is unsafe; caller already guarantees port validity.
        let portsc = unsafe { self.port_status(port)? };
        if portsc & PORT_CCS == 0 {
            return Err(Error::IoError);
        }
        let ls = portsc & PORT_LS_MASK;
        if ls == (1 << 10) {
            // K-state = low-speed
            Ok(UsbSpeed::Low)
        } else if portsc & PORT_PE != 0 {
            // Port enabled by EHCI = high-speed
            Ok(UsbSpeed::High)
        } else {
            Ok(UsbSpeed::Full)
        }
    }

    /// Resets a root hub port.
    ///
    /// Asserts PORT_RESET for at least 50 ms, then deasserts.
    ///
    /// # Safety
    /// `port` must be < `num_ports`.
    pub unsafe fn reset_port(&self, port: u8) -> Result<()> {
        if port >= self.num_ports {
            return Err(Error::InvalidArgument);
        }
        let offset = OPS_PORTSC_BASE + (port as u32) * 4;
        // SAFETY: Port reset sequence per USB spec §7.1.7.5.
        unsafe {
            let ps = read32(self.ops_base, offset);
            write32(self.ops_base, offset, (ps & !PORT_PE) | PORT_RESET);
            // Spin ~50 ms equivalent (calibrated spin loop)
            let mut spin = 2_000_000u32;
            while spin > 0 {
                spin -= 1;
                core::hint::spin_loop();
            }
            let ps2 = read32(self.ops_base, offset);
            write32(self.ops_base, offset, ps2 & !PORT_RESET);
            // Wait for reset to complete
            spin = 100_000;
            while read32(self.ops_base, offset) & PORT_RESET != 0 {
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }
        }
        Ok(())
    }

    /// Reads and clears the USBSTS interrupt status.
    ///
    /// # Safety
    /// Must be called from the interrupt handler.
    pub unsafe fn ack_interrupts(&self) -> u32 {
        // SAFETY: Write-1-to-clear semantics for status bits.
        unsafe {
            let sts = read32(self.ops_base, OPS_USBSTS);
            write32(self.ops_base, OPS_USBSTS, sts);
            sts
        }
    }

    /// Returns the HC Interface Version (BCD).
    ///
    /// # Safety
    /// Cap registers must be mapped.
    pub unsafe fn hci_version(&self) -> u16 {
        // SAFETY: Reading HCIVERSION from capability space.
        unsafe { (read32(self.cap_base, CAP_CAPLENGTH) >> 16) as u16 }
    }
}
