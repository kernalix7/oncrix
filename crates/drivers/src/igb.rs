// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel IGB Gigabit Ethernet driver.
//!
//! Supports the Intel 82575/82576/82580/I350/I354/I210/I211 Gigabit Ethernet
//! controllers. These are PCIe devices found in server and desktop NICs that
//! require MSI-X interrupt delivery and multi-queue operation.

use oncrix_lib::{Error, Result};

/// PCI vendor ID for Intel.
pub const IGB_VENDOR_ID: u16 = 0x8086;

/// Supported PCI device IDs.
pub const IGB_DEV_ID_82575EB_COPPER: u16 = 0x10A7;
pub const IGB_DEV_ID_82576: u16 = 0x10C9;
pub const IGB_DEV_ID_82580_COPPER: u16 = 0x150E;
pub const IGB_DEV_ID_I350_COPPER: u16 = 0x1521;
pub const IGB_DEV_ID_I210_COPPER: u16 = 0x1533;
pub const IGB_DEV_ID_I211_COPPER: u16 = 0x1539;

/// Register offsets (MMIO, relative to BAR0).
const REG_CTRL: u32 = 0x0000;
const REG_STATUS: u32 = 0x0008;
const REG_CTRL_EXT: u32 = 0x0018;
const REG_MDIC: u32 = 0x0020;
const REG_RCTL: u32 = 0x0100;
const REG_TCTL: u32 = 0x0400;
const REG_RDBAL: u32 = 0x2800;
const REG_RDBAH: u32 = 0x2804;
const REG_RDLEN: u32 = 0x2808;
const REG_RDH: u32 = 0x2810;
const REG_RDT: u32 = 0x2818;
const REG_RXDCTL: u32 = 0x2828;
const REG_TDBAL: u32 = 0x3800;
const REG_TDBAH: u32 = 0x3804;
const REG_TDLEN: u32 = 0x3808;
const REG_TDH: u32 = 0x3810;
const REG_TDT: u32 = 0x3818;
const REG_TXDCTL: u32 = 0x3828;
const REG_RAL0: u32 = 0x5400;
const REG_RAH0: u32 = 0x5404;
const REG_ICR: u32 = 0x00C0;
const REG_IMS: u32 = 0x00D0;
const REG_IMC: u32 = 0x00D8;

/// CTRL register bits.
const CTRL_FD: u32 = 1 << 0;
const CTRL_RST: u32 = 1 << 26;
const CTRL_VME: u32 = 1 << 30;

/// STATUS register bits.
const STATUS_LINK_UP: u32 = 1 << 1;
const STATUS_FD: u32 = 1 << 0;

/// RCTL register bits.
const RCTL_EN: u32 = 1 << 1;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_BSIZE_2K: u32 = 0 << 16;
const RCTL_SECRC: u32 = 1 << 26;

/// TCTL register bits.
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;
const TCTL_CT_SHIFT: u32 = 4;
const TCTL_COLD_SHIFT: u32 = 12;

/// Interrupt cause bits.
const ICR_TXDW: u32 = 1 << 0;
const ICR_RXDMT0: u32 = 1 << 4;
const ICR_RXO: u32 = 1 << 6;
const ICR_RXT0: u32 = 1 << 7;

/// Descriptor ring sizes.
const TX_RING_SIZE: usize = 256;
const RX_RING_SIZE: usize = 256;
const RX_BUFFER_SIZE: usize = 2048;

/// Transmit descriptor (advanced context format) `#[repr(C)]` for DMA.
#[repr(C)]
pub struct TxDesc {
    /// Buffer address (low 32 bits).
    pub buf_addr_lo: u32,
    /// Buffer address (high 32 bits).
    pub buf_addr_hi: u32,
    /// Command / type / length.
    pub cmd_type_len: u32,
    /// Status / OLINFO / PAYLEN.
    pub olinfo_status: u32,
}

impl TxDesc {
    /// Create a zeroed transmit descriptor.
    pub const fn new() -> Self {
        Self {
            buf_addr_lo: 0,
            buf_addr_hi: 0,
            cmd_type_len: 0,
            olinfo_status: 0,
        }
    }
}

impl Default for TxDesc {
    fn default() -> Self {
        Self::new()
    }
}

/// Receive descriptor (advanced 2-buffer format) `#[repr(C)]` for DMA.
#[repr(C)]
pub struct RxDesc {
    /// Packet buffer address (low).
    pub pkt_addr_lo: u32,
    /// Packet buffer address (high).
    pub pkt_addr_hi: u32,
    /// Header buffer address (low).
    pub hdr_addr_lo: u32,
    /// Header buffer address (high).
    pub hdr_addr_hi: u32,
}

impl RxDesc {
    /// Create a zeroed receive descriptor.
    pub const fn new() -> Self {
        Self {
            pkt_addr_lo: 0,
            pkt_addr_hi: 0,
            hdr_addr_lo: 0,
            hdr_addr_hi: 0,
        }
    }
}

impl Default for RxDesc {
    fn default() -> Self {
        Self::new()
    }
}

/// MAC address.
#[derive(Clone, Copy, Debug)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Zero/null MAC address.
    pub const ZERO: MacAddress = MacAddress([0u8; 6]);
}

/// IGB driver state.
pub struct IgbDriver {
    /// Base address of MMIO region (BAR0).
    mmio_base: usize,
    /// MAC address of this NIC.
    mac_address: MacAddress,
    /// Current TX ring head.
    tx_head: usize,
    /// Current TX ring tail.
    tx_tail: usize,
    /// Current RX ring tail.
    rx_tail: usize,
    /// Number of active TX queues.
    num_tx_queues: usize,
    /// Number of active RX queues.
    num_rx_queues: usize,
    /// Link is up.
    link_up: bool,
}

impl IgbDriver {
    /// Create a new IGB driver instance.
    ///
    /// # Arguments
    /// - `mmio_base`: physical address of the BAR0 MMIO region
    pub fn new(mmio_base: usize) -> Self {
        Self {
            mmio_base,
            mac_address: MacAddress::ZERO,
            tx_head: 0,
            tx_tail: 0,
            rx_tail: 0,
            num_tx_queues: 1,
            num_rx_queues: 1,
            link_up: false,
        }
    }

    /// Initialize the IGB controller.
    pub fn init(&mut self) -> Result<()> {
        self.global_reset()?;
        self.disable_interrupts();
        self.read_mac_address()?;
        self.configure_rx()?;
        self.configure_tx()?;
        self.enable_interrupts();
        Ok(())
    }

    /// Perform a global device reset.
    fn global_reset(&mut self) -> Result<()> {
        let ctrl = self.read32(REG_CTRL);
        self.write32(REG_CTRL, ctrl | CTRL_RST);
        // Spin until reset clears (real driver would use a timeout).
        let mut timeout = 0u32;
        loop {
            let ctrl_now = self.read32(REG_CTRL);
            if (ctrl_now & CTRL_RST) == 0 {
                break;
            }
            timeout += 1;
            if timeout > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }

    /// Mask all interrupt sources.
    fn disable_interrupts(&mut self) {
        self.write32(REG_IMC, 0xFFFF_FFFF);
    }

    /// Enable the standard interrupt set.
    fn enable_interrupts(&mut self) {
        self.write32(REG_IMS, ICR_TXDW | ICR_RXDMT0 | ICR_RXO | ICR_RXT0);
    }

    /// Read the MAC address from the Receive Address registers.
    fn read_mac_address(&mut self) -> Result<()> {
        let ral = self.read32(REG_RAL0);
        let rah = self.read32(REG_RAH0);
        let mut mac = [0u8; 6];
        mac[0] = (ral & 0xFF) as u8;
        mac[1] = ((ral >> 8) & 0xFF) as u8;
        mac[2] = ((ral >> 16) & 0xFF) as u8;
        mac[3] = ((ral >> 24) & 0xFF) as u8;
        mac[4] = (rah & 0xFF) as u8;
        mac[5] = ((rah >> 8) & 0xFF) as u8;
        self.mac_address = MacAddress(mac);
        Ok(())
    }

    /// Configure the receive unit.
    fn configure_rx(&mut self) -> Result<()> {
        let rctl = RCTL_EN | RCTL_BAM | RCTL_BSIZE_2K | RCTL_SECRC;
        self.write32(REG_RCTL, rctl);
        Ok(())
    }

    /// Configure the transmit unit.
    fn configure_tx(&mut self) -> Result<()> {
        let tctl = TCTL_EN | TCTL_PSP | (0x0F << TCTL_CT_SHIFT) | (0x40 << TCTL_COLD_SHIFT);
        self.write32(REG_TCTL, tctl);
        Ok(())
    }

    /// Transmit an Ethernet frame on queue 0.
    pub fn transmit(&mut self, frame: &[u8]) -> Result<()> {
        if frame.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let next = (self.tx_tail + 1) % TX_RING_SIZE;
        if next == self.tx_head {
            return Err(Error::Busy);
        }
        self.tx_tail = next;
        self.write32(REG_TDT, self.tx_tail as u32);
        Ok(())
    }

    /// Handle an interrupt; returns the ICR value.
    pub fn handle_interrupt(&mut self) -> u32 {
        let icr = self.read32(REG_ICR);
        if (icr & (ICR_RXT0 | ICR_RXDMT0)) != 0 {
            // Receive interrupt — caller should drain RX ring.
        }
        if (icr & ICR_TXDW) != 0 {
            // TX descriptor written back — reclaim completed descriptors.
            self.tx_head = self.read32(REG_TDH) as usize % TX_RING_SIZE;
        }
        icr
    }

    /// Return link status.
    pub fn is_link_up(&mut self) -> bool {
        let status = self.read32(REG_STATUS);
        self.link_up = (status & STATUS_LINK_UP) != 0;
        self.link_up
    }

    /// Return the MAC address.
    pub fn mac_address(&self) -> MacAddress {
        self.mac_address
    }

    // --- MMIO helpers ---

    fn read32(&self, offset: u32) -> u32 {
        let addr = (self.mmio_base + offset as usize) as *const u32;
        // SAFETY: mmio_base is a PCI BAR0 region mapped into the driver's address space;
        // all offsets are 4-byte aligned and within the 128-KiB register window.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write32(&mut self, offset: u32, val: u32) {
        let addr = (self.mmio_base + offset as usize) as *mut u32;
        // SAFETY: Same region as read32; volatile write ensures the store reaches hardware.
        unsafe { core::ptr::write_volatile(addr, val) }
    }
}
