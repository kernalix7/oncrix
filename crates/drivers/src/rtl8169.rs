// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Realtek RTL8169 Gigabit Ethernet driver.
//!
//! Implements a bare-metal driver for the Realtek RTL8168/RTL8169 GbE
//! controllers. Supports:
//! - MMIO register access
//! - TX/RX descriptor ring management (64-bit DMA)
//! - PHY auto-negotiation via PHYAR register
//! - Interrupt handling (TX OK, RX OK, Link change)
//!
//! # Hardware Model
//!
//! TX/RX paths use descriptor rings. Each descriptor contains a DMA
//! buffer address, control flags, and length. The NIC owns descriptors
//! when the OWN bit is set; the driver owns them when clear.
//!
//! Reference: RTL8169S/8110S Registers v1.0

use oncrix_lib::{Error, Result};

// ── MMIO Register Offsets ─────────────────────────────────────────────────────

/// MAC address registers 0-5.
const REG_MAC0: u32 = 0x00;
/// Multicast Address registers start.
const _REG_MAR0: u32 = 0x08;
/// Transmit Normal Priority Descriptor Start Address (64-bit, low).
const REG_TNPDS_L: u32 = 0x20;
/// Transmit Normal Priority Descriptor Start Address (64-bit, high).
const REG_TNPDS_H: u32 = 0x24;
/// Command register.
const REG_CR: u32 = 0x37;
/// TX Poll command.
const REG_TPPOLL: u32 = 0x38;
/// Interrupt Mask Register.
const REG_IMR: u32 = 0x3C;
/// Interrupt Status Register.
const REG_ISR: u32 = 0x3E;
/// TX Configuration.
const REG_TCR: u32 = 0x40;
/// RX Configuration.
const REG_RCR: u32 = 0x44;
/// 9346CR: EEPROM/Config unlock register.
const REG_9346CR: u32 = 0x50;
/// Config1 register.
const _REG_CONFIG1: u32 = 0x52;
/// PHY Access Register.
const REG_PHYAR: u32 = 0x60;
/// PHY Status register.
const REG_PHYSTATUS: u32 = 0x6C;
/// RX Descriptor Start Address Low.
const REG_RDSAR_L: u32 = 0xE4;
/// RX Descriptor Start Address High.
const REG_RDSAR_H: u32 = 0xE8;
/// Max RX Packet Size.
const REG_RMS: u32 = 0xDA;
/// TX Threshold register.
const _REG_ETTHR: u32 = 0xEC;
/// C+ command register.
const REG_CPCR: u32 = 0xE0;

// ── Bit fields ────────────────────────────────────────────────────────────────

/// CR: Receiver Enable.
const CR_RE: u8 = 1 << 3;
/// CR: Transmitter Enable.
const CR_TE: u8 = 1 << 2;
/// CR: Reset.
const CR_RST: u8 = 1 << 4;

/// ISR: Link Change.
const ISR_LINK_CHG: u16 = 1 << 5;
/// ISR: TX Error.
const ISR_TER: u16 = 1 << 3;
/// ISR: TX OK.
const ISR_TOK: u16 = 1 << 2;
/// ISR: RX Error.
const ISR_RER: u16 = 1 << 1;
/// ISR: RX OK.
const ISR_ROK: u16 = 1 << 0;

/// IMR: Enable all relevant interrupts.
const IMR_DEFAULT: u16 = ISR_ROK | ISR_RER | ISR_TOK | ISR_TER | ISR_LINK_CHG;

/// 9346CR: Config register write unlock.
const CR9346_EEM_UNLOCK: u8 = 0xC0;
/// 9346CR: Lock.
const CR9346_EEM_LOCK: u8 = 0x00;

/// RCR: Accept All Packets (promiscuous).
const RCR_AAP: u32 = 1 << 0;
/// RCR: Accept Broadcast.
const RCR_AB: u32 = 1 << 3;
/// RCR: Accept Multicast.
const RCR_AM: u32 = 1 << 2;
/// RCR: Accept Physical Match.
const RCR_APM: u32 = 1 << 1;
/// RCR: RX FIFO threshold (no threshold).
const RCR_RXFTH_NOLIMIT: u32 = 7 << 13;
/// RCR: Max DMA burst.
const RCR_MXDMA_UNLIMITED: u32 = 7 << 8;

/// TCR: TX FIFO threshold.
const TCR_MXDMA_UNLIMITED: u32 = 7 << 8;
/// TCR: IFG (96-bit inter-frame gap).
const TCR_IFG_NORMAL: u32 = 3 << 24;

/// C+ command: PCI dual-address cycle.
const CPCR_PCI_MULRW: u16 = 1 << 3;
/// C+ command: Enable RX checksumming.
const CPCR_RX_CHKSUM: u16 = 1 << 5;

/// PHYAR: Write bit.
const PHYAR_WRITE: u32 = 1 << 31;
/// PHYAR: Flag (indicates transfer complete).
const PHYAR_FLAG: u32 = 1 << 31;

/// Descriptor OWN bit: NIC owns this descriptor when set.
const DESC_OWN: u32 = 1 << 31;
/// Descriptor EOR: End of Ring marker.
const DESC_EOR: u32 = 1 << 30;
/// Descriptor First Segment (FS).
const DESC_FS: u32 = 1 << 29;
/// Descriptor Last Segment (LS).
const DESC_LS: u32 = 1 << 28;

// ── Ring sizes ────────────────────────────────────────────────────────────────

/// Number of TX descriptors.
const TX_RING_SIZE: usize = 64;
/// Number of RX descriptors.
const RX_RING_SIZE: usize = 64;
/// RX buffer size per descriptor.
const RX_BUF_SIZE: usize = 2048;
/// TX buffer size per descriptor.
const TX_BUF_SIZE: usize = 2048;
/// Maximum number of RTL8169 controllers.
const MAX_CONTROLLERS: usize = 4;

// ── Descriptor ────────────────────────────────────────────────────────────────

/// TX/RX descriptor ring entry (DMA-safe, 16 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, align(8))]
pub struct Desc {
    /// Control word: OWN | EOR | FS | LS | length.
    pub opts1: u32,
    /// Checksum offload options (TX) / VLAN tag (RX).
    pub opts2: u32,
    /// DMA buffer address low 32 bits.
    pub addr_lo: u32,
    /// DMA buffer address high 32 bits.
    pub addr_hi: u32,
}

impl Desc {
    /// Return the buffer length from opts1 (lower 13 bits).
    pub fn length(&self) -> u16 {
        (self.opts1 & 0x1FFF) as u16
    }

    /// Return whether the NIC owns this descriptor.
    pub fn is_owned(&self) -> bool {
        self.opts1 & DESC_OWN != 0
    }

    /// Return whether this is the last descriptor in the ring (EOR).
    pub fn is_eor(&self) -> bool {
        self.opts1 & DESC_EOR != 0
    }

    /// Set the DMA buffer address.
    pub fn set_addr(&mut self, addr: u64) {
        self.addr_lo = addr as u32;
        self.addr_hi = (addr >> 32) as u32;
    }

    /// Prepare as a TX descriptor (hand to NIC).
    pub fn setup_tx(&mut self, len: u16, eor: bool) {
        let mut opts = DESC_OWN | DESC_FS | DESC_LS | len as u32;
        if eor {
            opts |= DESC_EOR;
        }
        // SAFETY: opts1 is written with a volatile write for DMA sync.
        unsafe { core::ptr::write_volatile(&mut self.opts1, opts) };
    }

    /// Prepare as an RX descriptor (hand to NIC).
    pub fn setup_rx(&mut self, len: u16, eor: bool) {
        let mut opts = DESC_OWN | len as u32;
        if eor {
            opts |= DESC_EOR;
        }
        self.opts2 = 0;
        // SAFETY: opts1 write for DMA sync.
        unsafe { core::ptr::write_volatile(&mut self.opts1, opts) };
    }
}

// ── Rtl8169 ──────────────────────────────────────────────────────────────────

/// RTL8169 Gigabit Ethernet controller driver.
pub struct Rtl8169 {
    /// MMIO base virtual address.
    mmio_base: u64,
    /// TX descriptor ring.
    tx_ring: [Desc; TX_RING_SIZE],
    /// RX descriptor ring.
    rx_ring: [Desc; RX_RING_SIZE],
    /// TX data buffers.
    tx_buf: [[u8; TX_BUF_SIZE]; TX_RING_SIZE],
    /// RX data buffers.
    rx_buf: [[u8; RX_BUF_SIZE]; RX_RING_SIZE],
    /// TX head (next descriptor to be written by driver).
    tx_head: usize,
    /// TX tail (next descriptor to be reclaimed after TX).
    tx_tail: usize,
    /// RX head (next descriptor to be read by driver).
    rx_head: usize,
    /// MAC address.
    mac_addr: [u8; 6],
    /// Whether the controller is initialised.
    initialised: bool,
    /// Link speed in Mbps (0 = link down).
    link_speed_mbps: u16,
}

impl Rtl8169 {
    /// Create a new, uninitialised RTL8169 driver instance.
    pub const fn new() -> Self {
        Self {
            mmio_base: 0,
            tx_ring: [Desc {
                opts1: 0,
                opts2: 0,
                addr_lo: 0,
                addr_hi: 0,
            }; TX_RING_SIZE],
            rx_ring: [Desc {
                opts1: 0,
                opts2: 0,
                addr_lo: 0,
                addr_hi: 0,
            }; RX_RING_SIZE],
            tx_buf: [[0u8; TX_BUF_SIZE]; TX_RING_SIZE],
            rx_buf: [[0u8; RX_BUF_SIZE]; RX_RING_SIZE],
            tx_head: 0,
            tx_tail: 0,
            rx_head: 0,
            mac_addr: [0u8; 6],
            initialised: false,
            link_speed_mbps: 0,
        }
    }

    /// Initialise the RTL8169 controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `mmio_base` is zero.
    pub fn init(&mut self, mmio_base: u64) -> Result<()> {
        if mmio_base == 0 {
            return Err(Error::InvalidArgument);
        }
        self.mmio_base = mmio_base;

        // Software reset.
        self.write8(REG_CR, CR_RST);
        // Poll for reset completion (CR_RST clears when done).
        let mut timeout = 100_000u32;
        while self.read8(REG_CR) & CR_RST != 0 && timeout > 0 {
            timeout -= 1;
        }
        if timeout == 0 {
            return Err(Error::IoError);
        }

        // Read MAC address.
        for i in 0..6 {
            self.mac_addr[i] = self.read8(REG_MAC0 + i as u32);
        }

        // Unlock config registers.
        self.write8(REG_9346CR, CR9346_EEM_UNLOCK);

        // Enable RX/TX.
        self.write8(REG_CR, CR_RE | CR_TE);

        // Set RX configuration: accept broadcast + physical match.
        self.write32(
            REG_RCR,
            RCR_AB | RCR_APM | RCR_RXFTH_NOLIMIT | RCR_MXDMA_UNLIMITED,
        );

        // Set TX configuration.
        self.write32(REG_TCR, TCR_MXDMA_UNLIMITED | TCR_IFG_NORMAL);

        // Set max RX packet size (16 KiB - 1).
        self.write16(REG_RMS, 0x3FFF);

        // Enable C+ mode.
        self.write16(REG_CPCR, CPCR_PCI_MULRW | CPCR_RX_CHKSUM);

        // Initialise TX ring: all descriptors to driver, set EOR on last.
        for (i, desc) in self.tx_ring.iter_mut().enumerate() {
            let buf_addr = self.tx_buf[i].as_ptr() as u64;
            desc.set_addr(buf_addr);
            desc.opts1 = 0; // Not owned by NIC.
            if i == TX_RING_SIZE - 1 {
                desc.opts1 |= DESC_EOR;
            }
        }

        // Initialise RX ring: hand all descriptors to NIC.
        for (i, desc) in self.rx_ring.iter_mut().enumerate() {
            let buf_addr = self.rx_buf[i].as_ptr() as u64;
            desc.set_addr(buf_addr);
            let eor = i == RX_RING_SIZE - 1;
            desc.setup_rx(RX_BUF_SIZE as u16, eor);
        }

        // Write TX descriptor ring address.
        let tx_addr = self.tx_ring.as_ptr() as u64;
        self.write32(REG_TNPDS_L, tx_addr as u32);
        self.write32(REG_TNPDS_H, (tx_addr >> 32) as u32);

        // Write RX descriptor ring address.
        let rx_addr = self.rx_ring.as_ptr() as u64;
        self.write32(REG_RDSAR_L, rx_addr as u32);
        self.write32(REG_RDSAR_H, (rx_addr >> 32) as u32);

        // Enable interrupts.
        self.write16(REG_IMR, IMR_DEFAULT);

        // Lock config registers.
        self.write8(REG_9346CR, CR9346_EEM_LOCK);

        // Start auto-negotiation.
        self.phy_autoneg()?;

        self.initialised = true;
        Ok(())
    }

    // ── Register access ───────────────────────────────────────────────────

    fn read8(&self, reg: u32) -> u8 {
        // SAFETY: MMIO region is mapped; reg is a known-good offset.
        unsafe { core::ptr::read_volatile((self.mmio_base + reg as u64) as *const u8) }
    }

    fn read16(&self, reg: u32) -> u16 {
        // SAFETY: Same as read8.
        unsafe { core::ptr::read_volatile((self.mmio_base + reg as u64) as *const u16) }
    }

    fn read32(&self, reg: u32) -> u32 {
        // SAFETY: Same as read8.
        unsafe { core::ptr::read_volatile((self.mmio_base + reg as u64) as *const u32) }
    }

    fn write8(&self, reg: u32, val: u8) {
        // SAFETY: MMIO write to known register.
        unsafe { core::ptr::write_volatile((self.mmio_base + reg as u64) as *mut u8, val) }
    }

    fn write16(&self, reg: u32, val: u16) {
        // SAFETY: Same as write8.
        unsafe { core::ptr::write_volatile((self.mmio_base + reg as u64) as *mut u16, val) }
    }

    fn write32(&self, reg: u32, val: u32) {
        // SAFETY: Same as write8.
        unsafe { core::ptr::write_volatile((self.mmio_base + reg as u64) as *mut u32, val) }
    }

    // ── PHY access ────────────────────────────────────────────────────────

    /// Read a PHY register via the PHYAR indirect register.
    fn phy_read(&self, reg: u8) -> Result<u16> {
        let cmd = ((reg as u32) & 0x1F) << 16;
        self.write32(REG_PHYAR, cmd);
        let mut timeout = 10_000u32;
        loop {
            let val = self.read32(REG_PHYAR);
            if val & PHYAR_FLAG != 0 {
                return Ok(val as u16);
            }
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }
    }

    /// Write a PHY register via PHYAR.
    fn phy_write(&self, reg: u8, data: u16) -> Result<()> {
        let cmd = PHYAR_WRITE | (((reg as u32) & 0x1F) << 16) | data as u32;
        self.write32(REG_PHYAR, cmd);
        let mut timeout = 10_000u32;
        loop {
            if self.read32(REG_PHYAR) & PHYAR_FLAG == 0 {
                return Ok(());
            }
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }
    }

    /// Start GbE auto-negotiation via PHY registers.
    fn phy_autoneg(&self) -> Result<()> {
        // PHY reg 0: Control; set auto-negotiation enable + restart.
        let mut ctrl = self.phy_read(0)?;
        ctrl |= (1 << 12) | (1 << 9); // AN enable + restart AN
        self.phy_write(0, ctrl)
    }

    // ── TX / RX ───────────────────────────────────────────────────────────

    /// Transmit a packet.
    ///
    /// Copies `data` into the next available TX buffer and triggers
    /// a TX poll.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the TX ring is full,
    /// [`Error::InvalidArgument`] if `data` exceeds TX buffer size.
    pub fn send_packet(&mut self, data: &[u8]) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        if data.len() > TX_BUF_SIZE {
            return Err(Error::InvalidArgument);
        }
        // Check if NIC still owns the head descriptor.
        if self.tx_ring[self.tx_head].is_owned() {
            return Err(Error::Busy);
        }

        let idx = self.tx_head;
        self.tx_buf[idx][..data.len()].copy_from_slice(data);

        let eor = idx == TX_RING_SIZE - 1;
        let buf_addr = self.tx_buf[idx].as_ptr() as u64;
        self.tx_ring[idx].set_addr(buf_addr);
        self.tx_ring[idx].setup_tx(data.len() as u16, eor);

        self.tx_head = (self.tx_head + 1) % TX_RING_SIZE;

        // Trigger TX by polling.
        self.write8(REG_TPPOLL, 0x40); // NPQ bit
        Ok(())
    }

    /// Receive a packet if one is available.
    ///
    /// Copies received data into `buf` and returns the number of bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if no packet is available (RX ring has no
    /// driver-owned descriptors with data), or [`Error::InvalidArgument`]
    /// if `buf` is too small.
    pub fn recv_packet(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }

        let desc = &self.rx_ring[self.rx_head];
        // SAFETY: Reading opts1 with volatile for DMA sync.
        let opts1 = unsafe { core::ptr::read_volatile(&desc.opts1) };
        if opts1 & DESC_OWN != 0 {
            return Err(Error::Busy);
        }

        let pkt_len = (opts1 & 0x3FFF) as usize;
        if pkt_len > 4 {
            // strip 4-byte CRC
            let data_len = pkt_len - 4;
            if buf.len() < data_len {
                return Err(Error::InvalidArgument);
            }
            buf[..data_len].copy_from_slice(&self.rx_buf[self.rx_head][..data_len]);

            // Return descriptor to NIC.
            let eor = self.rx_head == RX_RING_SIZE - 1;
            let buf_addr = self.rx_buf[self.rx_head].as_ptr() as u64;
            self.rx_ring[self.rx_head].set_addr(buf_addr);
            self.rx_ring[self.rx_head].setup_rx(RX_BUF_SIZE as u16, eor);

            self.rx_head = (self.rx_head + 1) % RX_RING_SIZE;
            return Ok(data_len);
        }
        Err(Error::Busy)
    }

    /// Handle an interrupt.
    ///
    /// Reads and clears the Interrupt Status Register.
    /// Returns the ISR value (caller checks ISR_ROK, ISR_TOK, etc.).
    pub fn handle_interrupt(&mut self) -> u16 {
        let isr = self.read16(REG_ISR);
        // Clear by writing back.
        self.write16(REG_ISR, isr);

        if isr & ISR_LINK_CHG != 0 {
            // Update link speed from PHY status.
            let physt = self.read8(REG_PHYSTATUS);
            self.link_speed_mbps = match physt & 0x1C {
                0x08 => 10,
                0x04 => 100,
                0x02 => 1000,
                _ => 0,
            };
        }
        isr
    }

    /// Return the MAC address.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_addr
    }

    /// Return the current link speed in Mbps (0 = link down).
    pub fn link_speed_mbps(&self) -> u16 {
        self.link_speed_mbps
    }

    /// Return whether the link is up.
    pub fn link_is_up(&self) -> bool {
        self.link_speed_mbps > 0
    }
}

impl Default for Rtl8169 {
    fn default() -> Self {
        Self::new()
    }
}

// ── Registry ──────────────────────────────────────────────────────────────────

/// Global RTL8169 controller registry.
pub struct Rtl8169Registry {
    controllers: [Option<Rtl8169>; MAX_CONTROLLERS],
    count: usize,
}

impl Rtl8169Registry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            controllers: [const { None }; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Register a new RTL8169 controller.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, ctrl: Rtl8169) -> Result<usize> {
        if self.count >= MAX_CONTROLLERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.controllers[idx] = Some(ctrl);
        self.count += 1;
        Ok(idx)
    }

    /// Return a mutable reference to a controller by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut Rtl8169> {
        self.controllers.get_mut(idx)?.as_mut()
    }

    /// Return the number of registered controllers.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for Rtl8169Registry {
    fn default() -> Self {
        Self::new()
    }
}
