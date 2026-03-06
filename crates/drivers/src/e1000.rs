// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel E1000/E1000e network interface card driver.
//!
//! Implements a bare-metal driver for the Intel 82540EM (E1000) family
//! of Gigabit Ethernet controllers using memory-mapped I/O. Supports
//! packet transmission, reception, interrupt handling, and MAC address
//! configuration.
//!
//! # Architecture
//!
//! - **MMIO registers** — control/status, receive/transmit configuration
//! - **RX ring** — 128 receive descriptors with 2048-byte buffers
//! - **TX ring** — 128 transmit descriptors with 2048-byte buffers
//! - **Interrupts** — ICR/IMS/IMC for interrupt cause and masking
//!
//! Reference: Intel 82540EM Software Developer's Manual.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// MMIO Register Offsets
// ---------------------------------------------------------------------------

/// Device Control register.
const _REG_CTRL: u32 = 0x0000;

/// Device Status register.
const REG_STATUS: u32 = 0x0008;

/// EEPROM Read register.
const _REG_EERD: u32 = 0x0014;

/// Interrupt Cause Read register.
const REG_ICR: u32 = 0x00C0;

/// Interrupt Mask Set register.
const REG_IMS: u32 = 0x00D0;

/// Interrupt Mask Clear register.
const _REG_IMC: u32 = 0x00D8;

/// Receive Control register.
const REG_RCTL: u32 = 0x0100;

/// Transmit Control register.
const REG_TCTL: u32 = 0x0400;

/// Receive Descriptor Base Address Low.
const REG_RDBAL: u32 = 0x2800;

/// Receive Descriptor Length.
const REG_RDLEN: u32 = 0x2808;

/// Receive Descriptor Head.
const REG_RDH: u32 = 0x2810;

/// Receive Descriptor Tail.
const REG_RDT: u32 = 0x2818;

/// Transmit Descriptor Base Address Low.
const REG_TDBAL: u32 = 0x3800;

/// Transmit Descriptor Length.
const REG_TDLEN: u32 = 0x3808;

/// Transmit Descriptor Head.
const REG_TDH: u32 = 0x3810;

/// Transmit Descriptor Tail.
const REG_TDT: u32 = 0x3818;

/// Receive Address Low (unicast entry 0).
const REG_RAL0: u32 = 0x5400;

/// Receive Address High (unicast entry 0).
const REG_RAH0: u32 = 0x5404;

/// Multicast Table Array (start).
const _REG_MTA: u32 = 0x5200;

// ---------------------------------------------------------------------------
// Control / Status bits
// ---------------------------------------------------------------------------

/// CTRL: Software Reset.
const CTRL_RST: u32 = 1 << 26;

/// CTRL: Set Link Up.
const _CTRL_SLU: u32 = 1 << 6;

/// STATUS: Link Up.
const STATUS_LU: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Receive Control bits
// ---------------------------------------------------------------------------

/// RCTL: Receiver Enable.
const RCTL_EN: u32 = 1 << 1;

/// RCTL: Unicast Promiscuous.
const _RCTL_UPE: u32 = 1 << 3;

/// RCTL: Multicast Promiscuous.
const _RCTL_MPE: u32 = 1 << 4;

/// RCTL: Broadcast Accept Mode.
const RCTL_BAM: u32 = 1 << 15;

/// RCTL: Buffer Size 2048 bytes (BSIZE=0, BSEX=0).
const RCTL_BSIZE_2048: u32 = 0;

/// RCTL: Strip Ethernet CRC.
const RCTL_SECRC: u32 = 1 << 26;

// ---------------------------------------------------------------------------
// Transmit Control bits
// ---------------------------------------------------------------------------

/// TCTL: Transmit Enable.
const TCTL_EN: u32 = 1 << 1;

/// TCTL: Pad Short Packets.
const TCTL_PSP: u32 = 1 << 3;

/// TCTL: Collision Threshold (shift position).
const _TCTL_CT_SHIFT: u32 = 4;

/// TCTL: Collision Distance (shift position).
const _TCTL_COLD_SHIFT: u32 = 12;

// ---------------------------------------------------------------------------
// Interrupt bits
// ---------------------------------------------------------------------------

/// IMS: Transmit Descriptor Written Back.
const IMS_TXDW: u32 = 1 << 0;

/// IMS: Receive Descriptor Minimum Threshold.
const _IMS_RXDMT0: u32 = 1 << 4;

/// IMS: Receiver FIFO Overrun.
const _IMS_RXO: u32 = 1 << 6;

/// IMS: Receive Timer Interrupt.
const IMS_RXT0: u32 = 1 << 7;

/// IMS: Link Status Change.
const IMS_LSC: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// Buffer and queue constants
// ---------------------------------------------------------------------------

/// Number of receive descriptors in the ring.
pub const RX_DESC_COUNT: usize = 128;

/// Number of transmit descriptors in the ring.
pub const TX_DESC_COUNT: usize = 128;

/// Size of each receive/transmit buffer in bytes.
pub const BUF_SIZE: usize = 2048;

/// Maximum Ethernet frame size (MTU 1500 + headers).
pub const MAX_PACKET_SIZE: usize = 1518;

/// Maximum number of E1000 devices in the registry.
pub const MAX_E1000_DEVICES: usize = 4;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

/// Read a 32-bit value from MMIO space at `base + offset`.
///
/// # Safety
///
/// The caller must ensure that `base + offset` is a valid,
/// mapped MMIO address aligned to 4 bytes.
fn read_mmio32(base: u64, offset: u32) -> u32 {
    // SAFETY: The caller guarantees that the address is valid,
    // mapped, and properly aligned for a 32-bit MMIO read.
    unsafe {
        let addr = (base + u64::from(offset)) as *const u32;
        core::ptr::read_volatile(addr)
    }
}

/// Write a 32-bit value to MMIO space at `base + offset`.
///
/// # Safety
///
/// The caller must ensure that `base + offset` is a valid,
/// mapped MMIO address aligned to 4 bytes.
fn write_mmio32(base: u64, offset: u32, val: u32) {
    // SAFETY: The caller guarantees that the address is valid,
    // mapped, and properly aligned for a 32-bit MMIO write.
    unsafe {
        let addr = (base + u64::from(offset)) as *mut u32;
        core::ptr::write_volatile(addr, val);
    }
}

// ---------------------------------------------------------------------------
// Receive Descriptor
// ---------------------------------------------------------------------------

/// E1000 receive descriptor (§3.2.3).
///
/// Each descriptor is 16 bytes and describes a receive buffer that
/// the hardware writes incoming packets into.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct RxDescriptor {
    /// Physical address of the receive buffer.
    pub buffer_addr: u64,
    /// Length of the received data (set by hardware).
    pub length: u16,
    /// Packet checksum (set by hardware).
    pub checksum: u16,
    /// Descriptor status bits (set by hardware).
    pub status: u8,
    /// Descriptor error bits (set by hardware).
    pub errors: u8,
    /// Special / VLAN tag (set by hardware).
    pub special: u16,
}

/// Receive descriptor status: Descriptor Done.
const RXD_STAT_DD: u8 = 1 << 0;

/// Receive descriptor status: End of Packet.
const RXD_STAT_EOP: u8 = 1 << 1;

impl RxDescriptor {
    /// Create a zeroed receive descriptor.
    const fn zeroed() -> Self {
        Self {
            buffer_addr: 0,
            length: 0,
            checksum: 0,
            status: 0,
            errors: 0,
            special: 0,
        }
    }

    /// Check if the hardware has finished writing to this descriptor.
    pub fn is_done(&self) -> bool {
        self.status & RXD_STAT_DD != 0
    }

    /// Check if this descriptor marks the end of a received packet.
    pub fn is_eop(&self) -> bool {
        self.status & RXD_STAT_EOP != 0
    }
}

impl core::fmt::Debug for RxDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RxDescriptor")
            .field("buffer_addr", &self.buffer_addr)
            .field("length", &self.length)
            .field("status", &self.status)
            .field("errors", &self.errors)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Transmit Descriptor
// ---------------------------------------------------------------------------

/// Transmit descriptor command bit: End of Packet.
pub const TXD_CMD_EOP: u8 = 1 << 0;

/// Transmit descriptor command bit: Insert FCS/CRC.
pub const TXD_CMD_IFCS: u8 = 1 << 1;

/// Transmit descriptor command bit: Report Status.
pub const TXD_CMD_RS: u8 = 1 << 3;

/// Transmit descriptor status bit: Descriptor Done.
const TXD_STAT_DD: u8 = 1 << 0;

/// E1000 transmit descriptor (§3.3.3).
///
/// Each descriptor is 16 bytes and describes a transmit buffer that
/// the hardware reads outgoing packets from.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct TxDescriptor {
    /// Physical address of the transmit buffer.
    pub buffer_addr: u64,
    /// Length of the data to transmit.
    pub length: u16,
    /// Checksum offset.
    pub cso: u8,
    /// Command bits (EOP, IFCS, RS, etc.).
    pub cmd: u8,
    /// Descriptor status bits (set by hardware).
    pub status: u8,
    /// Checksum start.
    pub css: u8,
    /// Special / VLAN tag.
    pub special: u16,
}

impl TxDescriptor {
    /// Create a zeroed transmit descriptor.
    const fn zeroed() -> Self {
        Self {
            buffer_addr: 0,
            length: 0,
            cso: 0,
            cmd: 0,
            status: 0,
            css: 0,
            special: 0,
        }
    }

    /// Check if the hardware has finished transmitting this descriptor.
    pub fn is_done(&self) -> bool {
        self.status & TXD_STAT_DD != 0
    }
}

impl core::fmt::Debug for TxDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxDescriptor")
            .field("buffer_addr", &self.buffer_addr)
            .field("length", &self.length)
            .field("cmd", &self.cmd)
            .field("status", &self.status)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// MAC Address
// ---------------------------------------------------------------------------

/// A 6-byte IEEE 802.3 MAC address.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Create a MAC address from raw bytes.
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Return the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Format the MAC address as a colon-separated hex string.
    ///
    /// Writes `XX:XX:XX:XX:XX:XX` into the provided formatter.
    pub fn format(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            a, b, c, d, e, g
        )
    }
}

impl core::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.format(f)
    }
}

impl core::fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "MacAddress({})", self)
    }
}

// ---------------------------------------------------------------------------
// E1000 Device
// ---------------------------------------------------------------------------

/// Intel E1000/E1000e network interface card driver.
///
/// Manages a single E1000 NIC through MMIO registers. Provides
/// transmit and receive functionality via descriptor rings backed
/// by statically allocated buffers.
///
/// # Usage
///
/// ```ignore
/// let mut nic = E1000Device::new(mmio_base_address);
/// nic.init()?;
/// nic.send(&ethernet_frame)?;
/// ```
pub struct E1000Device {
    /// Base address of the MMIO register space.
    mmio_base: u64,
    /// Receive descriptor ring.
    rx_ring: [RxDescriptor; RX_DESC_COUNT],
    /// Transmit descriptor ring.
    tx_ring: [TxDescriptor; TX_DESC_COUNT],
    /// Receive packet buffers.
    rx_buffers: [[u8; BUF_SIZE]; RX_DESC_COUNT],
    /// Transmit packet buffers.
    tx_buffers: [[u8; BUF_SIZE]; TX_DESC_COUNT],
    /// Current receive ring tail index.
    rx_tail: usize,
    /// Current transmit ring tail index.
    tx_tail: usize,
    /// Device MAC address.
    mac_address: MacAddress,
    /// Whether the link is up.
    link_up: bool,
    /// Whether the device has been initialized.
    initialized: bool,
}

/// Empty receive descriptor for const initialization.
const EMPTY_RX_DESC: RxDescriptor = RxDescriptor::zeroed();

/// Empty transmit descriptor for const initialization.
const EMPTY_TX_DESC: TxDescriptor = TxDescriptor::zeroed();

/// Empty buffer for const initialization.
const EMPTY_BUF: [u8; BUF_SIZE] = [0u8; BUF_SIZE];

impl E1000Device {
    /// Create a new E1000 driver for a device at `mmio_base`.
    ///
    /// The device is not usable until [`init`](Self::init) is called.
    pub const fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            rx_ring: [EMPTY_RX_DESC; RX_DESC_COUNT],
            tx_ring: [EMPTY_TX_DESC; TX_DESC_COUNT],
            rx_buffers: [EMPTY_BUF; RX_DESC_COUNT],
            tx_buffers: [EMPTY_BUF; TX_DESC_COUNT],
            rx_tail: 0,
            tx_tail: 0,
            mac_address: MacAddress([0; 6]),
            link_up: false,
            initialized: false,
        }
    }

    /// Initialize the E1000 device.
    ///
    /// Performs the following steps:
    /// 1. Software reset via CTRL register
    /// 2. Read MAC address from RAL0/RAH0
    /// 3. Initialize receive descriptor ring
    /// 4. Initialize transmit descriptor ring
    /// 5. Enable interrupts (link status change, RX, TX)
    /// 6. Check link status
    pub fn init(&mut self) -> Result<()> {
        // Step 1: Software reset.
        let ctrl = self.read_reg(_REG_CTRL);
        self.write_reg(_REG_CTRL, ctrl | CTRL_RST);

        // Wait for reset to complete (RST bit self-clears).
        let mut timeout = 1_000_000u32;
        while self.read_reg(_REG_CTRL) & CTRL_RST != 0 {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }

        // Step 2: Read MAC address.
        self.mac_address = self.read_mac();

        // Step 3: Set up receive ring.
        self.setup_rx();

        // Step 4: Set up transmit ring.
        self.setup_tx();

        // Step 5: Enable interrupts.
        self.write_reg(REG_IMS, IMS_LSC | IMS_RXT0 | IMS_TXDW);

        // Step 6: Check link status.
        self.link_up = self.link_status();

        self.initialized = true;
        Ok(())
    }

    /// Read a 32-bit MMIO register at the given offset.
    pub fn read_reg(&self, offset: u32) -> u32 {
        read_mmio32(self.mmio_base, offset)
    }

    /// Write a 32-bit value to an MMIO register at the given offset.
    pub fn write_reg(&mut self, offset: u32, val: u32) {
        write_mmio32(self.mmio_base, offset, val);
    }

    /// Read the MAC address from the RAL0 and RAH0 registers.
    pub fn read_mac(&self) -> MacAddress {
        let ral = self.read_reg(REG_RAL0);
        let rah = self.read_reg(REG_RAH0);
        MacAddress([
            ral as u8,
            (ral >> 8) as u8,
            (ral >> 16) as u8,
            (ral >> 24) as u8,
            rah as u8,
            (rah >> 8) as u8,
        ])
    }

    /// Configure the receive descriptor ring and enable reception.
    ///
    /// Sets up each RX descriptor to point at its corresponding
    /// buffer, programs RDBAL/RDLEN/RDH/RDT, and enables RCTL.
    pub fn setup_rx(&mut self) {
        // Point each descriptor at its buffer.
        let mut i = 0;
        while i < RX_DESC_COUNT {
            self.rx_ring[i].buffer_addr = self.rx_buffers[i].as_ptr() as u64;
            self.rx_ring[i].status = 0;
            i += 1;
        }

        // Program the receive descriptor ring registers.
        let rdbal = self.rx_ring.as_ptr() as u64;
        self.write_reg(REG_RDBAL, rdbal as u32);
        self.write_reg(
            REG_RDLEN,
            (RX_DESC_COUNT * core::mem::size_of::<RxDescriptor>()) as u32,
        );
        self.write_reg(REG_RDH, 0);
        self.write_reg(REG_RDT, (RX_DESC_COUNT - 1) as u32);

        self.rx_tail = 0;

        // Enable receiver: accept broadcast, 2048-byte buffers,
        // strip CRC.
        self.write_reg(REG_RCTL, RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC);
    }

    /// Configure the transmit descriptor ring and enable transmission.
    ///
    /// Sets up each TX descriptor to point at its corresponding
    /// buffer, programs TDBAL/TDLEN/TDH/TDT, and enables TCTL.
    pub fn setup_tx(&mut self) {
        // Point each descriptor at its buffer and mark as done.
        let mut i = 0;
        while i < TX_DESC_COUNT {
            self.tx_ring[i].buffer_addr = self.tx_buffers[i].as_ptr() as u64;
            self.tx_ring[i].status = TXD_STAT_DD;
            self.tx_ring[i].cmd = 0;
            i += 1;
        }

        // Program the transmit descriptor ring registers.
        let tdbal = self.tx_ring.as_ptr() as u64;
        self.write_reg(REG_TDBAL, tdbal as u32);
        self.write_reg(
            REG_TDLEN,
            (TX_DESC_COUNT * core::mem::size_of::<TxDescriptor>()) as u32,
        );
        self.write_reg(REG_TDH, 0);
        self.write_reg(REG_TDT, 0);

        self.tx_tail = 0;

        // Enable transmitter: enable + pad short packets.
        // Collision threshold = 15, collision distance = 64.
        let tctl = TCTL_EN | TCTL_PSP | (15 << _TCTL_CT_SHIFT) | (64 << _TCTL_COLD_SHIFT);
        self.write_reg(REG_TCTL, tctl);
    }

    /// Transmit an Ethernet frame.
    ///
    /// Copies `data` into the next available TX buffer and submits
    /// the descriptor to hardware. Returns an error if the packet
    /// exceeds [`MAX_PACKET_SIZE`] or the device is not initialized.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if data.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if data.len() > MAX_PACKET_SIZE {
            return Err(Error::InvalidArgument);
        }

        let idx = self.tx_tail;

        // Wait for the descriptor to be available (DD set).
        if !self.tx_ring[idx].is_done() {
            return Err(Error::WouldBlock);
        }

        // Copy packet data into the TX buffer.
        let buf = &mut self.tx_buffers[idx];
        buf[..data.len()].copy_from_slice(data);

        // Set up the descriptor.
        self.tx_ring[idx].length = data.len() as u16;
        self.tx_ring[idx].cmd = TXD_CMD_EOP | TXD_CMD_IFCS | TXD_CMD_RS;
        self.tx_ring[idx].status = 0;

        // Advance tail and notify hardware.
        self.tx_tail = (idx + 1) % TX_DESC_COUNT;
        self.write_reg(REG_TDT, self.tx_tail as u32);

        Ok(())
    }

    /// Poll for a received packet.
    ///
    /// If a completed receive descriptor is available, returns
    /// `Some((descriptor_index, length))`. The caller can then read
    /// the packet data from the corresponding receive buffer.
    /// Returns `None` if no packet is ready.
    pub fn receive(&mut self) -> Option<(usize, usize)> {
        if !self.initialized {
            return None;
        }

        let idx = self.rx_tail;

        if !self.rx_ring[idx].is_done() {
            return None;
        }

        let length = self.rx_ring[idx].length as usize;

        // Reset the descriptor for reuse.
        self.rx_ring[idx].status = 0;
        self.rx_ring[idx].length = 0;

        // Advance the tail and notify hardware.
        let old_idx = idx;
        self.rx_tail = (idx + 1) % RX_DESC_COUNT;
        self.write_reg(REG_RDT, idx as u32);

        Some((old_idx, length))
    }

    /// Handle an E1000 interrupt.
    ///
    /// Reads and returns the Interrupt Cause Read (ICR) register.
    /// Reading ICR automatically acknowledges the pending interrupts.
    /// The caller should inspect the returned bits to determine the
    /// cause (e.g., RX timer, TX writeback, link status change).
    pub fn handle_interrupt(&mut self) -> u32 {
        let icr = self.read_reg(REG_ICR);

        // Update link status if a link status change occurred.
        if icr & IMS_LSC != 0 {
            self.link_up = self.link_status();
        }

        icr
    }

    /// Check whether the physical link is up.
    ///
    /// Reads the STATUS register and returns `true` if the Link Up
    /// (LU) bit is set.
    pub fn link_status(&self) -> bool {
        self.read_reg(REG_STATUS) & STATUS_LU != 0
    }

    /// Return the device's MAC address.
    pub fn mac_address(&self) -> MacAddress {
        self.mac_address
    }

    /// Check if the device has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Return a reference to the receive buffer at `index`.
    ///
    /// Returns `None` if `index` is out of range.
    pub fn rx_buffer(&self, index: usize) -> Option<&[u8; BUF_SIZE]> {
        self.rx_buffers.get(index)
    }
}

impl core::fmt::Debug for E1000Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("E1000Device")
            .field("mmio_base", &self.mmio_base)
            .field("mac_address", &self.mac_address)
            .field("link_up", &self.link_up)
            .field("initialized", &self.initialized)
            .field("rx_tail", &self.rx_tail)
            .field("tx_tail", &self.tx_tail)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// E1000 Registry
// ---------------------------------------------------------------------------

/// Registry for tracking multiple E1000 devices.
///
/// Supports up to [`MAX_E1000_DEVICES`] concurrently registered
/// devices, identified by their MMIO base address.
pub struct E1000Registry {
    /// Registered MMIO base addresses (`0` means empty slot).
    bases: [u64; MAX_E1000_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for E1000Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl E1000Registry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            bases: [0; MAX_E1000_DEVICES],
            count: 0,
        }
    }

    /// Register a new E1000 device by its MMIO base address.
    ///
    /// Returns an error if the registry is full or the device is
    /// already registered.
    pub fn register(&mut self, mmio_base: u64) -> Result<()> {
        if mmio_base == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.bases[..self.count].contains(&mmio_base) {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_E1000_DEVICES {
            return Err(Error::OutOfMemory);
        }
        self.bases[self.count] = mmio_base;
        self.count += 1;
        Ok(())
    }

    /// Look up a registered device by MMIO base address.
    ///
    /// Returns the index of the device in the registry, or
    /// `Err(NotFound)` if not registered.
    pub fn lookup(&self, mmio_base: u64) -> Result<usize> {
        self.bases[..self.count]
            .iter()
            .position(|&b| b == mmio_base)
            .ok_or(Error::NotFound)
    }

    /// Return the number of registered devices.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return the MMIO base address at the given index.
    ///
    /// Returns `None` if `index` is out of range.
    pub fn get(&self, index: usize) -> Option<u64> {
        if index < self.count {
            Some(self.bases[index])
        } else {
            None
        }
    }
}

impl core::fmt::Debug for E1000Registry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("E1000Registry")
            .field("count", &self.count)
            .field("bases", &&self.bases[..self.count])
            .finish()
    }
}
