// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NE2000 (DP8390) ISA/PCI NIC driver.
//!
//! Implements a driver for the NS DP8390 "NE2000 compatible" Ethernet
//! controller. The NE2000 uses port I/O exclusively and is widely emulated
//! in QEMU (ISA NE2000 and PCI NE2000).
//!
//! # Architecture
//!
//! - **Page 0**: Command, data transfer, interrupt registers
//! - **Page 1**: Physical/multicast address registers, current page pointer
//! - **Page 2** (diagnostic): Transmit page start, FIFO threshold, etc.
//! - **Remote DMA**: Used to read/write NIC internal buffer (ring buffer)
//!
//! # NE2000 Internal Buffer Layout
//!
//! The NIC has a 16 KiB internal SRAM buffer:
//! - TX buffer: pages 0x40–0x46 (6 × 256 = 1536 bytes, one packet)
//! - RX ring:   pages 0x46–0x80
//!
//! Reference: National Semiconductor DP8390D/NS32490D NIC Specification.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// I/O Port Register Offsets (page-selected)
// ---------------------------------------------------------------------------

// -- Page 0 (read/write) --

/// Command Register (CR) — select page, start/stop, DMA.
const REG_CR: u16 = 0x00;
/// Current Local DMA Address 0 (CLDA0).
const _REG_CLDA0: u16 = 0x01;
/// Page Start Register (PSTART, write).
const REG_PSTART: u16 = 0x01;
/// Current Local DMA Address 1 (CLDA1).
const _REG_CLDA1: u16 = 0x02;
/// Page Stop Register (PSTOP, write).
const REG_PSTOP: u16 = 0x02;
/// Boundary Pointer (BNRY).
const REG_BNRY: u16 = 0x03;
/// Transmit Page Start (TPSR, write).
const REG_TPSR: u16 = 0x04;
/// Transmit Status Register (TSR, read).
const _REG_TSR: u16 = 0x04;
/// Transmit Byte Count Low (TBCR0, write).
const REG_TBCR0: u16 = 0x05;
/// Transmit Byte Count High (TBCR1, write).
const REG_TBCR1: u16 = 0x06;
/// Interrupt Status Register (ISR).
const REG_ISR: u16 = 0x07;
/// Remote Start Address 0 (RSAR0, write).
const REG_RSAR0: u16 = 0x08;
/// Remote Start Address 1 (RSAR1, write).
const REG_RSAR1: u16 = 0x09;
/// Remote Byte Count 0 (RBCR0, write).
const REG_RBCR0: u16 = 0x0A;
/// Remote Byte Count 1 (RBCR1, write).
const REG_RBCR1: u16 = 0x0B;
/// Receive Configuration Register (RCR, write).
const REG_RCR: u16 = 0x0C;
/// Receive Status Register (RSR, read).
const _REG_RSR: u16 = 0x0C;
/// Transmit Configuration Register (TCR, write).
const REG_TCR: u16 = 0x0D;
/// Data Configuration Register (DCR, write).
const REG_DCR: u16 = 0x0E;
/// Interrupt Mask Register (IMR, write).
const REG_IMR: u16 = 0x0F;
/// Data Port (for remote DMA transfers, 16-bit wide on NE2000).
const REG_DATA: u16 = 0x10;
/// Reset Port.
const REG_RESET: u16 = 0x1F;

// -- Page 1 offsets --

/// Physical Address Register 0 (PAR0).
const REG_PAR0: u16 = 0x01;
/// Current Page (CURR).
const REG_CURR: u16 = 0x07;
/// Multicast Address Register 0 (MAR0).
const _REG_MAR0: u16 = 0x08;

// ---------------------------------------------------------------------------
// CR bits
// ---------------------------------------------------------------------------

/// CR: Stop (reset state).
const CR_STOP: u8 = 0x01;
/// CR: Start (run).
const CR_START: u8 = 0x02;
/// CR: Transmit.
const CR_TXP: u8 = 0x04;
/// CR: Remote DMA Read.
const CR_RREAD: u8 = 0x08;
/// CR: Remote DMA Write.
const CR_RWRITE: u8 = 0x10;
/// CR: Abort/Complete Remote DMA.
const CR_NODMA: u8 = 0x20;
/// CR: Page select bits [7:6].
const CR_PAGE0: u8 = 0x00;
const CR_PAGE1: u8 = 0x40;
const _CR_PAGE2: u8 = 0x80;

// ---------------------------------------------------------------------------
// ISR bits
// ---------------------------------------------------------------------------

/// ISR: Packet Received.
const ISR_PRX: u8 = 0x01;
/// ISR: Packet Transmitted.
const ISR_PTX: u8 = 0x02;
/// ISR: Receive Error.
const ISR_RXE: u8 = 0x04;
/// ISR: Transmit Error.
const ISR_TXE: u8 = 0x08;
/// ISR: Overwrite Warning.
const ISR_OVW: u8 = 0x10;
/// ISR: Counter Overflow.
const _ISR_CNT: u8 = 0x20;
/// ISR: Remote DMA Complete.
const ISR_RDC: u8 = 0x40;
/// ISR: Reset Status.
const _ISR_RST: u8 = 0x80;

// ---------------------------------------------------------------------------
// DCR bits
// ---------------------------------------------------------------------------

/// DCR: Word Transfer Select (16-bit DMA).
const DCR_WTS: u8 = 0x01;
/// DCR: Byte Order Select (little-endian).
const DCR_BOS: u8 = 0x02;
/// DCR: FIFO Threshold = 8 bytes.
const DCR_FT1: u8 = 0x40;

// ---------------------------------------------------------------------------
// Buffer layout (in NIC pages, 1 page = 256 bytes)
// ---------------------------------------------------------------------------

/// TX buffer start page.
const TX_START_PAGE: u8 = 0x40;
/// RX ring start page (after TX).
const RX_START_PAGE: u8 = 0x46;
/// RX ring stop page (end of 16K buffer).
const RX_STOP_PAGE: u8 = 0x80;

// ---------------------------------------------------------------------------
// Receive header (prepended to each received packet in NIC SRAM)
// ---------------------------------------------------------------------------

/// Receive Status byte in NE2000 packet header.
const RXHDR_STATUS: usize = 0;
/// Next page pointer in NE2000 packet header.
const RXHDR_NEXT: usize = 1;
/// Packet length low byte.
const RXHDR_LEN_LO: usize = 2;
/// Packet length high byte.
const RXHDR_LEN_HI: usize = 3;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum Ethernet packet size (including header, no FCS).
pub const ETH_MAX_FRAME: usize = 1514;
/// RX timeout in DMA completion poll loops.
const RDC_TIMEOUT: u32 = 10_000;

// ---------------------------------------------------------------------------
// Ne2k driver
// ---------------------------------------------------------------------------

/// NE2000 (DP8390) NIC driver.
pub struct Ne2k {
    /// Base I/O port.
    base: u16,
    /// MAC address.
    mac_addr: [u8; 6],
    /// Current RX read page.
    next_packet: u8,
    /// Whether the driver is initialized.
    initialized: bool,
}

impl Ne2k {
    /// Creates a new NE2000 driver instance.
    pub const fn new(base: u16) -> Self {
        Self {
            base,
            mac_addr: [0u8; 6],
            next_packet: RX_START_PAGE,
            initialized: false,
        }
    }

    /// Initializes the NE2000 hardware.
    ///
    /// Resets the chip, reads the MAC PROM, configures the RX ring and
    /// TX buffer, and enables the RX engine.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `base` is zero.
    /// Returns [`Error::IoError`] if reset fails or DMA times out.
    pub fn init(&mut self) -> Result<()> {
        if self.base == 0 {
            return Err(Error::InvalidArgument);
        }

        // Reset by reading the RESET port.
        self.outb(REG_RESET, self.inb(REG_RESET));
        // Wait for ISR_RST.
        let mut reset_done = false;
        for _ in 0..10_000u32 {
            if self.inb(REG_ISR) & 0x80 != 0 {
                reset_done = true;
                break;
            }
        }
        if !reset_done {
            return Err(Error::IoError);
        }

        // Stop, select page 0, no DMA.
        self.outb(REG_CR, CR_PAGE0 | CR_NODMA | CR_STOP);
        // Word-wide DMA, little-endian, FIFO threshold.
        self.outb(REG_DCR, DCR_WTS | DCR_BOS | DCR_FT1);
        // Clear remote byte count.
        self.outb(REG_RBCR0, 0);
        self.outb(REG_RBCR1, 0);
        // Accept broadcast, no errors, no runt packets.
        self.outb(REG_RCR, 0x04); // AB = accept broadcast
        // Transmit normal mode.
        self.outb(REG_TCR, 0x02); // LOOP internal
        // Set TX/RX pages.
        self.outb(REG_TPSR, TX_START_PAGE);
        self.outb(REG_PSTART, RX_START_PAGE);
        self.outb(REG_PSTOP, RX_STOP_PAGE);
        self.outb(REG_BNRY, RX_START_PAGE);
        // Clear ISR.
        self.outb(REG_ISR, 0xFF);
        // Mask all interrupts.
        self.outb(REG_IMR, 0x00);

        // Switch to page 1 to set CURR and read MAC PROM.
        self.outb(REG_CR, CR_PAGE1 | CR_NODMA | CR_STOP);
        self.outb(REG_CURR, RX_START_PAGE + 1);
        // Read 6 bytes of MAC from NIC SRAM (PROM at offset 0).
        self.mac_addr = self.read_mac_prom()?;
        // Program PAR0-5.
        for (i, &b) in self.mac_addr.iter().enumerate() {
            self.outb(REG_PAR0 + i as u16, b);
        }
        // Clear multicast table (accept none by default).
        for i in 0..8u16 {
            self.outb(0x08 + i, 0x00);
        }

        // Back to page 0, start.
        self.outb(REG_CR, CR_PAGE0 | CR_NODMA | CR_START);
        // Normal transmit mode (no loopback).
        self.outb(REG_TCR, 0x00);
        // Enable RX/TX interrupts.
        self.outb(REG_IMR, ISR_PRX | ISR_PTX | ISR_RXE | ISR_TXE | ISR_OVW);

        self.next_packet = RX_START_PAGE + 1;
        self.initialized = true;
        Ok(())
    }

    /// Handles an interrupt: reads ISR, dispatches, returns cause bitmask.
    pub fn handle_irq(&mut self) -> u8 {
        let isr = self.inb(REG_ISR);
        // Acknowledge all pending interrupts.
        self.outb(REG_ISR, isr);
        isr
    }

    /// Returns `true` if a received packet is available in the RX ring.
    pub fn has_rx_packet(&self) -> bool {
        let curr = self.read_curr_page();
        curr != self.next_packet
    }

    /// Transmits a packet by copying into NIC SRAM via remote DMA.
    ///
    /// `buf` must be at most `ETH_MAX_FRAME` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `buf` is empty or too large.
    /// Returns [`Error::IoError`] if DMA completion times out.
    pub fn transmit(&mut self, buf: &[u8]) -> Result<()> {
        if buf.is_empty() || buf.len() > ETH_MAX_FRAME {
            return Err(Error::InvalidArgument);
        }
        // Pad to minimum Ethernet frame size.
        let len = if buf.len() < 60 { 60 } else { buf.len() };

        // Remote DMA write to TX_START_PAGE.
        self.rdma_write(TX_START_PAGE, buf, len)?;

        // Issue transmit command.
        self.outb(REG_TPSR, TX_START_PAGE);
        self.outb(REG_TBCR0, (len & 0xFF) as u8);
        self.outb(REG_TBCR1, (len >> 8) as u8);
        self.outb(REG_CR, CR_PAGE0 | CR_NODMA | CR_START | CR_TXP);
        Ok(())
    }

    /// Returns the MAC address.
    pub fn mac_addr(&self) -> [u8; 6] {
        self.mac_addr
    }

    /// Returns `true` if the driver is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn read_curr_page(&self) -> u8 {
        // Must switch to page 1 to read CURR.
        self.outb(REG_CR, CR_PAGE1 | CR_NODMA | CR_START);
        let curr = self.inb(REG_CURR);
        self.outb(REG_CR, CR_PAGE0 | CR_NODMA | CR_START);
        curr
    }

    fn rdma_write(&self, page: u8, buf: &[u8], padded_len: usize) -> Result<()> {
        let offset = (page as u16) << 8;
        // Set remote DMA address and count.
        self.outb(REG_RSAR0, (offset & 0xFF) as u8);
        self.outb(REG_RSAR1, (offset >> 8) as u8);
        self.outb(REG_RBCR0, (padded_len & 0xFF) as u8);
        self.outb(REG_RBCR1, (padded_len >> 8) as u8);
        // Start remote write DMA.
        self.outb(REG_CR, CR_PAGE0 | CR_RWRITE | CR_START);
        // Write payload (16-bit words).
        let words = buf.len() / 2;
        for i in 0..words {
            let w = u16::from_le_bytes([buf[i * 2], buf[i * 2 + 1]]);
            self.outw(REG_DATA, w);
        }
        if buf.len() % 2 == 1 {
            self.outw(REG_DATA, buf[buf.len() - 1] as u16);
        }
        // Pad to padded_len if needed.
        let remaining = padded_len.saturating_sub(buf.len());
        for _ in 0..(remaining / 2) {
            self.outw(REG_DATA, 0);
        }
        // Wait for remote DMA complete.
        for _ in 0..RDC_TIMEOUT {
            if self.inb(REG_ISR) & ISR_RDC != 0 {
                self.outb(REG_ISR, ISR_RDC);
                return Ok(());
            }
        }
        Err(Error::IoError)
    }

    fn read_mac_prom(&self) -> Result<[u8; 6]> {
        // NE2000 PROM: first 6 words at NIC SRAM offset 0.
        // Each word holds one MAC byte (byte duplicated in high/low).
        let mut mac = [0u8; 6];
        // Remote DMA read from SRAM offset 0, 12 bytes (6 words).
        self.outb(REG_RSAR0, 0);
        self.outb(REG_RSAR1, 0);
        self.outb(REG_RBCR0, 12);
        self.outb(REG_RBCR1, 0);
        self.outb(REG_CR, CR_PAGE1 | CR_RREAD | CR_START);
        // Oops — need to be page 0 for data port access.
        self.outb(REG_CR, CR_PAGE0 | CR_RREAD | CR_START);
        for i in 0..6 {
            let w = self.inw(REG_DATA);
            mac[i] = (w & 0xFF) as u8;
        }
        // Drain remaining 0 bytes of remote DMA.
        for _ in 0..RDC_TIMEOUT {
            if self.inb(REG_ISR) & ISR_RDC != 0 {
                self.outb(REG_ISR, ISR_RDC);
                break;
            }
        }
        Ok(mac)
    }

    fn inb(&self, offset: u16) -> u8 {
        port_inb(self.base + offset)
    }

    fn outb(&self, offset: u16, val: u8) {
        port_outb(self.base + offset, val);
    }

    fn inw(&self, offset: u16) -> u16 {
        port_inw(self.base + offset)
    }

    fn outw(&self, offset: u16, val: u16) {
        port_outw(self.base + offset, val);
    }
}

impl Default for Ne2k {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
fn port_inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Port read is a privileged I/O instruction permitted in kernel mode.
    unsafe { core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack)) };
    val
}

#[cfg(not(target_arch = "x86_64"))]
fn port_inb(_port: u16) -> u8 {
    0
}

#[cfg(target_arch = "x86_64")]
fn port_outb(port: u16, val: u8) {
    // SAFETY: Port write is a privileged I/O instruction permitted in kernel mode.
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack)) };
}

#[cfg(not(target_arch = "x86_64"))]
fn port_outb(_port: u16, _val: u8) {}

#[cfg(target_arch = "x86_64")]
fn port_inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: 16-bit port read permitted in kernel mode.
    unsafe { core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack)) };
    val
}

#[cfg(not(target_arch = "x86_64"))]
fn port_inw(_port: u16) -> u16 {
    0
}

#[cfg(target_arch = "x86_64")]
fn port_outw(port: u16, val: u16) {
    // SAFETY: 16-bit port write permitted in kernel mode.
    unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack)) };
}

#[cfg(not(target_arch = "x86_64"))]
fn port_outw(_port: u16, _val: u16) {}
