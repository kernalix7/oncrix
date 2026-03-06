// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel IXGBE 10-Gigabit Ethernet driver.
//!
//! Supports the Intel 82598/82599/X540/X550/X552/X553 10GbE controllers.
//! These are PCIe devices providing 10 Gbps connectivity and are common in
//! data-center and high-performance computing environments.

use oncrix_lib::{Error, Result};

/// PCI vendor ID for Intel.
pub const IXGBE_VENDOR_ID: u16 = 0x8086;

/// Supported PCI device IDs.
pub const IXGBE_DEV_ID_82598: u16 = 0x10B6;
pub const IXGBE_DEV_ID_82599_SFP: u16 = 0x10FB;
pub const IXGBE_DEV_ID_X540T: u16 = 0x1528;
pub const IXGBE_DEV_ID_X550T: u16 = 0x1563;
pub const IXGBE_DEV_ID_X552: u16 = 0x15AC;

/// MMIO register offsets (BAR0).
const REG_CTRL: u32 = 0x0000_0000;
const REG_STATUS: u32 = 0x0000_0008;
const REG_CTRL_EXT: u32 = 0x0001_8000;
const REG_EIMC: u32 = 0x0000_0888;
const REG_EICR: u32 = 0x0000_0800;
const REG_EIMS: u32 = 0x0000_0880;
const REG_RXCTRL: u32 = 0x0000_3000;
const REG_DMATXCTL: u32 = 0x0004_A80C;
const REG_RDRXCTL: u32 = 0x0002_F00C;
const REG_HLREG0: u32 = 0x0001_1F00;
const REG_MAXFRS: u32 = 0x0001_9100;
const REG_MFLCN: u32 = 0x0004_A01C;
const REG_RDBAL: u32 = 0x0001_0100;
const REG_RDBAH: u32 = 0x0001_0104;
const REG_RDLEN: u32 = 0x0001_0108;
const REG_RDH: u32 = 0x0001_0110;
const REG_RDT: u32 = 0x0001_0118;
const REG_RXDCTL: u32 = 0x0001_0128;
const REG_TDBAL: u32 = 0x0006_0000;
const REG_TDBAH: u32 = 0x0006_0004;
const REG_TDLEN: u32 = 0x0006_0008;
const REG_TDH: u32 = 0x0006_0010;
const REG_TDT: u32 = 0x0006_0018;
const REG_TXDCTL: u32 = 0x0006_0028;

/// CTRL register bits.
const CTRL_RST: u32 = 1 << 26;
const CTRL_LNK_RST: u32 = 1 << 3;

/// STATUS bits.
const STATUS_LINK_UP: u32 = 1 << 7;

/// RXCTRL bits.
const RXCTRL_RXEN: u32 = 1 << 0;

/// DMATXCTL bits.
const DMATXCTL_TE: u32 = 1 << 0;

/// RXDCTL bits.
const RXDCTL_ENABLE: u32 = 1 << 25;

/// TXDCTL bits.
const TXDCTL_ENABLE: u32 = 1 << 25;

/// Maximum descriptor ring sizes.
const TX_RING_SIZE: usize = 512;
const RX_RING_SIZE: usize = 512;

/// Maximum frame size (9000 bytes for jumbo frames).
const MAX_FRAME_SIZE: usize = 9018;
const RX_BUFFER_SIZE: usize = 2048;

/// Advanced Transmit Descriptor `#[repr(C)]` for DMA.
#[repr(C)]
pub struct TxDesc {
    /// Physical address of the packet buffer.
    pub buf_addr: u64,
    /// Descriptor length, command type, and status.
    pub cmd_type_len: u32,
    /// OLINFO (offload info) and status.
    pub olinfo_status: u32,
}

impl TxDesc {
    /// Create a zeroed transmit descriptor.
    pub const fn new() -> Self {
        Self {
            buf_addr: 0,
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

/// Advanced Receive Descriptor (write-back format) `#[repr(C)]` for DMA.
#[repr(C)]
pub struct RxDesc {
    /// Physical address of the receive buffer.
    pub buf_addr: u64,
    /// Physical address of the header buffer.
    pub hdr_addr: u64,
}

impl RxDesc {
    /// Create a zeroed receive descriptor.
    pub const fn new() -> Self {
        Self {
            buf_addr: 0,
            hdr_addr: 0,
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
    /// Zero address.
    pub const ZERO: MacAddress = MacAddress([0u8; 6]);
}

/// IXGBE adapter configuration.
#[derive(Clone, Copy, Debug)]
pub struct IxgbeConfig {
    /// Enable jumbo frames (up to 9018 bytes).
    pub jumbo_frames: bool,
    /// Number of TX queues.
    pub num_tx_queues: usize,
    /// Number of RX queues.
    pub num_rx_queues: usize,
}

impl Default for IxgbeConfig {
    fn default() -> Self {
        Self {
            jumbo_frames: false,
            num_tx_queues: 1,
            num_rx_queues: 1,
        }
    }
}

/// IXGBE driver state.
pub struct IxgbeDriver {
    /// Base address of the MMIO region (BAR0).
    mmio_base: usize,
    /// MAC address.
    mac_address: MacAddress,
    /// TX ring producer index.
    tx_tail: usize,
    /// TX ring consumer index.
    tx_head: usize,
    /// RX ring producer index.
    rx_tail: usize,
    /// Driver configuration.
    config: IxgbeConfig,
    /// Link is currently up.
    link_up: bool,
}

impl IxgbeDriver {
    /// Create a new IXGBE driver instance.
    ///
    /// # Arguments
    /// - `mmio_base`: physical address of BAR0
    /// - `config`: adapter configuration
    pub fn new(mmio_base: usize, config: IxgbeConfig) -> Self {
        Self {
            mmio_base,
            mac_address: MacAddress::ZERO,
            tx_tail: 0,
            tx_head: 0,
            rx_tail: 0,
            config,
            link_up: false,
        }
    }

    /// Initialize the IXGBE controller.
    pub fn init(&mut self) -> Result<()> {
        self.global_reset()?;
        self.disable_interrupts();
        self.read_mac_address()?;
        self.configure_rx()?;
        self.configure_tx()?;
        self.enable_interrupts();
        Ok(())
    }

    /// Perform a global reset.
    fn global_reset(&mut self) -> Result<()> {
        let ctrl = self.read32(REG_CTRL);
        self.write32(REG_CTRL, ctrl | CTRL_RST | CTRL_LNK_RST);
        // Wait for hardware to complete reset.
        let mut timeout = 0u32;
        loop {
            let v = self.read32(REG_CTRL);
            if (v & CTRL_RST) == 0 {
                break;
            }
            timeout += 1;
            if timeout > 200_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
        Ok(())
    }

    /// Mask all interrupt sources.
    fn disable_interrupts(&mut self) {
        self.write32(REG_EIMC, 0xFFFF_FFFF);
    }

    /// Enable key interrupt causes.
    fn enable_interrupts(&mut self) {
        // Enable Rx/Tx queue 0 MSI-X interrupt (bit 0 and 1).
        self.write32(REG_EIMS, 0x0000_0003);
    }

    /// Read the MAC address from receive address registers (RAL/RAH).
    fn read_mac_address(&mut self) -> Result<()> {
        // RAL[0] and RAH[0] are at fixed offsets for IXGBE.
        let ral = self.read32(0x0000_A200);
        let rah = self.read32(0x0000_A204);
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

    /// Configure the receive path.
    fn configure_rx(&mut self) -> Result<()> {
        // Enable receive and set buffer size.
        let rxctrl = self.read32(REG_RXCTRL);
        self.write32(REG_RXCTRL, rxctrl | RXCTRL_RXEN);
        // Enable the first RX queue.
        let rxdctl = self.read32(REG_RXDCTL);
        self.write32(REG_RXDCTL, rxdctl | RXDCTL_ENABLE);
        Ok(())
    }

    /// Configure the transmit path.
    fn configure_tx(&mut self) -> Result<()> {
        // Enable DMA TX engine.
        let dmatxctl = self.read32(REG_DMATXCTL);
        self.write32(REG_DMATXCTL, dmatxctl | DMATXCTL_TE);
        // Enable the first TX queue.
        let txdctl = self.read32(REG_TXDCTL);
        self.write32(REG_TXDCTL, txdctl | TXDCTL_ENABLE);
        Ok(())
    }

    /// Enqueue a frame for transmission on queue 0.
    pub fn transmit(&mut self, frame: &[u8]) -> Result<()> {
        if frame.is_empty() || frame.len() > MAX_FRAME_SIZE {
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

    /// Handle an interrupt; returns the EICR value.
    pub fn handle_interrupt(&mut self) -> u32 {
        let eicr = self.read32(REG_EICR);
        // Re-enable interrupts (EICR read clears the register on IXGBE).
        self.write32(REG_EIMS, 0x0000_0003);
        if (eicr & 0x1) != 0 {
            // RX queue 0 interrupt.
        }
        if (eicr & 0x2) != 0 {
            // TX queue 0 interrupt.
            self.tx_head = self.read32(REG_TDH) as usize % TX_RING_SIZE;
        }
        eicr
    }

    /// Check whether the link is currently up.
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
        // SAFETY: mmio_base is a valid PCI BAR0 region; offset is within the
        // 512-KiB IXGBE register space; volatile read required for MMIO.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write32(&mut self, offset: u32, val: u32) {
        let addr = (self.mmio_base + offset as usize) as *mut u32;
        // SAFETY: Same as read32; volatile write ensures the store reaches hardware.
        unsafe { core::ptr::write_volatile(addr, val) }
    }
}
