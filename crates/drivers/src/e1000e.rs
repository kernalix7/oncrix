// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel e1000e Gigabit Ethernet controller driver.
//!
//! Supports the e1000e family (82574, 82577, 82578, 82579, I217, I218, I219)
//! using memory-mapped registers. Implements receive/transmit ring management
//! for 1 Gbps operation.
//!
//! # Architecture
//! - **Register access**: MMIO via BAR0 (32-bit aligned register reads/writes).
//! - **RX ring**: 128 receive descriptors with 2048-byte packet buffers.
//! - **TX ring**: 128 transmit descriptors with 2048-byte packet buffers.
//! - **Interrupts**: ICR/IMS/IMC for masking and status.
//!
//! Reference: Intel Ethernet Controller I217 Datasheet; Intel 82574L GbE Datasheet.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Ring Sizes
// ---------------------------------------------------------------------------

/// Number of RX/TX ring descriptors.
const RING_SIZE: usize = 128;
/// Packet buffer size per descriptor.
const BUFFER_SIZE: usize = 2048;
/// Maximum number of e1000e controllers tracked.
const MAX_CONTROLLERS: usize = 4;

// ---------------------------------------------------------------------------
// MMIO Register Offsets
// ---------------------------------------------------------------------------

/// CTRL: Device Control.
const REG_CTRL: u32 = 0x0000;
/// STATUS: Device Status.
const REG_STATUS: u32 = 0x0008;
/// EERD: EEPROM Read.
const _REG_EERD: u32 = 0x0014;
/// CTRL_EXT: Extended Device Control.
const _REG_CTRL_EXT: u32 = 0x0018;
/// ICR: Interrupt Cause Read (cleared on read).
const REG_ICR: u32 = 0x00C0;
/// ITR: Interrupt Throttling Rate.
const _REG_ITR: u32 = 0x00C4;
/// IMS: Interrupt Mask Set/Read.
const REG_IMS: u32 = 0x00D0;
/// IMC: Interrupt Mask Clear.
const REG_IMC: u32 = 0x00D8;
/// RCTL: Receive Control.
const REG_RCTL: u32 = 0x0100;
/// TCTL: Transmit Control.
const REG_TCTL: u32 = 0x0400;
/// TIPG: Transmit Inter Packet Gap.
const REG_TIPG: u32 = 0x0410;
/// RDBAL: Receive Descriptor Base Address Low.
const REG_RDBAL: u32 = 0x2800;
/// RDBAH: Receive Descriptor Base Address High.
const REG_RDBAH: u32 = 0x2804;
/// RDLEN: Receive Descriptor Length (bytes).
const REG_RDLEN: u32 = 0x2808;
/// RDH: Receive Descriptor Head.
const REG_RDH: u32 = 0x2810;
/// RDT: Receive Descriptor Tail.
const REG_RDT: u32 = 0x2818;
/// TDBAL: Transmit Descriptor Base Address Low.
const REG_TDBAL: u32 = 0x3800;
/// TDBAH: Transmit Descriptor Base Address High.
const REG_TDBAH: u32 = 0x3804;
/// TDLEN: Transmit Descriptor Length (bytes).
const REG_TDLEN: u32 = 0x3808;
/// TDH: Transmit Descriptor Head.
const REG_TDH: u32 = 0x3810;
/// TDT: Transmit Descriptor Tail.
const REG_TDT: u32 = 0x3818;
/// RAL0: Receive Address Low (first unicast entry).
const REG_RAL0: u32 = 0x5400;
/// RAH0: Receive Address High (first unicast entry).
const REG_RAH0: u32 = 0x5404;

// ---------------------------------------------------------------------------
// CTRL Register Bits
// ---------------------------------------------------------------------------

/// CTRL: Full Duplex.
const CTRL_FD: u32 = 1 << 0;
/// CTRL: Speed select 1000 Mbps (bits 9:8 = 10).
const CTRL_SPEED_1000: u32 = 2 << 8;
/// CTRL: Force Speed.
const _CTRL_FRCSPD: u32 = 1 << 11;
/// CTRL: Force Duplex.
const _CTRL_FRCDPX: u32 = 1 << 12;
/// CTRL: Reset.
const CTRL_RST: u32 = 1 << 26;
/// CTRL: PHY Reset.
const CTRL_PHY_RST: u32 = 1 << 31;

// ---------------------------------------------------------------------------
// RCTL Bits
// ---------------------------------------------------------------------------

/// RCTL: Receiver Enable.
const RCTL_EN: u32 = 1 << 1;
/// RCTL: Store Bad Packets.
const _RCTL_SBP: u32 = 1 << 2;
/// RCTL: Unicast Promiscuous Mode.
const _RCTL_UPE: u32 = 1 << 3;
/// RCTL: Multicast Promiscuous Mode.
const _RCTL_MPE: u32 = 1 << 4;
/// RCTL: Long Packet Reception Enable (> 1522 bytes).
const _RCTL_LPE: u32 = 1 << 5;
/// RCTL: Loopback Mode (bits 7:6 = 00 = no loopback).
const _RCTL_LBM_NONE: u32 = 0;
/// RCTL: Buffer size 2048 bytes (BSIZE bits 17:16 = 00, BSEX=0).
const RCTL_BSIZE_2048: u32 = 0;
/// RCTL: Broadcast Accept Mode.
const RCTL_BAM: u32 = 1 << 15;
/// RCTL: Strip Ethernet CRC.
const RCTL_SECRC: u32 = 1 << 26;

// ---------------------------------------------------------------------------
// TCTL Bits
// ---------------------------------------------------------------------------

/// TCTL: Transmit Enable.
const TCTL_EN: u32 = 1 << 1;
/// TCTL: Pad Short Packets.
const TCTL_PSP: u32 = 1 << 3;
/// TCTL: Collision Threshold (bits 11:4 = 0x0F for 1 Gbps).
const TCTL_CT_1GBPS: u32 = 0x0F << 4;
/// TCTL: Collision Distance (bits 21:12 = 0x040 for 1 Gbps).
const TCTL_COLD_1GBPS: u32 = 0x040 << 12;

// ---------------------------------------------------------------------------
// ICR / IMS Bits
// ---------------------------------------------------------------------------

/// Interrupt: Transmit Descriptor Written Back.
const ICR_TXDW: u32 = 1 << 0;
/// Interrupt: Link Status Change.
const ICR_LSC: u32 = 1 << 2;
/// Interrupt: Receive Sequence Error.
const _ICR_RXSEQ: u32 = 1 << 3;
/// Interrupt: Receive Descriptor Minimum Threshold.
const ICR_RXDMT0: u32 = 1 << 4;
/// Interrupt: Receiver Overrun.
const _ICR_RXO: u32 = 1 << 6;
/// Interrupt: Receiver Timer Interrupt (packet received).
const ICR_RXT0: u32 = 1 << 7;

// ---------------------------------------------------------------------------
// Status Register
// ---------------------------------------------------------------------------

/// STATUS: Link Up.
const STATUS_LU: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// Receive Descriptor
// ---------------------------------------------------------------------------

/// Legacy receive descriptor.
///
/// `#[repr(C)]` required for DMA.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RxDesc {
    /// Physical address of the packet buffer.
    pub addr: u64,
    /// Number of bytes received (written by hardware).
    pub length: u16,
    /// Checksum (written by hardware).
    pub checksum: u16,
    /// Status bits (DD = Descriptor Done).
    pub status: u8,
    /// Errors.
    pub errors: u8,
    /// Special field.
    pub special: u16,
}

/// RX descriptor status: Descriptor Done (DD) bit.
pub const RX_STATUS_DD: u8 = 1 << 0;
/// RX descriptor status: End of Packet (EOP) bit.
pub const RX_STATUS_EOP: u8 = 1 << 1;

// ---------------------------------------------------------------------------
// Transmit Descriptor (Legacy)
// ---------------------------------------------------------------------------

/// Legacy transmit descriptor.
///
/// `#[repr(C)]` required for DMA.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TxDesc {
    /// Physical address of the packet buffer.
    pub addr: u64,
    /// Packet length in bytes.
    pub length: u16,
    /// Checksum Start field.
    pub cso: u8,
    /// Command bits (EOP | IFCS | RS).
    pub cmd: u8,
    /// Status/Reserved byte (DD = Descriptor Done when RS set).
    pub status: u8,
    /// Checksum Offset.
    pub css: u8,
    /// Special field.
    pub special: u16,
}

/// TX command: End of Packet.
pub const TX_CMD_EOP: u8 = 1 << 0;
/// TX command: Insert FCS (Ethernet CRC).
pub const TX_CMD_IFCS: u8 = 1 << 1;
/// TX command: Report Status (set DD when done).
pub const TX_CMD_RS: u8 = 1 << 3;
/// TX status: Descriptor Done.
pub const TX_STATUS_DD: u8 = 1 << 0;

// ---------------------------------------------------------------------------
// MMIO Helpers
// ---------------------------------------------------------------------------

/// Reads a 32-bit MMIO register.
///
/// # Safety
/// `base + offset` must be a valid mapped e1000e register address.
#[inline]
unsafe fn read_mmio32(base: u64, offset: u32) -> u32 {
    let ptr = (base + offset as u64) as *const u32;
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::read_volatile(ptr) }
}

/// Writes a 32-bit MMIO register.
///
/// # Safety
/// See `read_mmio32`.
#[inline]
unsafe fn write_mmio32(base: u64, offset: u32, val: u32) {
    let ptr = (base + offset as u64) as *mut u32;
    // SAFETY: Caller guarantees valid MMIO address.
    unsafe { core::ptr::write_volatile(ptr, val) }
}

// ---------------------------------------------------------------------------
// E1000e NIC Driver
// ---------------------------------------------------------------------------

/// Intel e1000e NIC driver.
pub struct E1000e {
    /// Virtual base address of the MMIO BAR0 region.
    mmio_base: u64,
    /// RX ring head index.
    rx_head: usize,
    /// TX ring tail index.
    tx_tail: usize,
}

impl E1000e {
    /// Creates a new `E1000e` driver for the given MMIO base.
    pub const fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            rx_head: 0,
            tx_tail: 0,
        }
    }

    /// Initializes the NIC: resets, programs MAC, sets up RX/TX rings.
    ///
    /// # Parameters
    /// - `rx_desc_phys`: Physical address of the RX descriptor ring.
    /// - `tx_desc_phys`: Physical address of the TX descriptor ring.
    /// - `mac`: 6-byte MAC address.
    ///
    /// # Safety
    /// `mmio_base` must be mapped. Descriptor ring physical addresses must be
    /// valid DMA-accessible memory aligned to 16 bytes.
    pub unsafe fn init(
        &mut self,
        rx_desc_phys: u64,
        tx_desc_phys: u64,
        mac: [u8; 6],
    ) -> Result<()> {
        // SAFETY: e1000e initialization sequence per Intel datasheet §14.3.
        unsafe {
            // Reset device
            write_mmio32(self.mmio_base, REG_CTRL, CTRL_RST);
            // Brief wait for reset to complete
            let mut spin = 10_000u32;
            while read_mmio32(self.mmio_base, REG_CTRL) & CTRL_RST != 0 {
                if spin == 0 {
                    return Err(Error::Busy);
                }
                spin -= 1;
                core::hint::spin_loop();
            }

            // Clear all interrupt masks
            write_mmio32(self.mmio_base, REG_IMC, 0xFFFF_FFFF);

            // Program MAC address into RAL0/RAH0
            self.set_mac_address(mac);

            // Initialize RX
            self.init_rx(rx_desc_phys)?;

            // Initialize TX
            self.init_tx(tx_desc_phys)?;

            // Enable link
            let ctrl = read_mmio32(self.mmio_base, REG_CTRL);
            write_mmio32(self.mmio_base, REG_CTRL, ctrl | CTRL_FD | CTRL_SPEED_1000);

            // Enable interrupts: RX timer, link change, TX done
            write_mmio32(
                self.mmio_base,
                REG_IMS,
                ICR_RXT0 | ICR_LSC | ICR_TXDW | ICR_RXDMT0,
            );
        }
        Ok(())
    }

    /// Programs the MAC address.
    ///
    /// # Safety
    /// MMIO base must be mapped.
    unsafe fn set_mac_address(&self, mac: [u8; 6]) {
        // SAFETY: Writing RAL0/RAH0 programs the first unicast filter entry.
        unsafe {
            let ral = (mac[0] as u32)
                | ((mac[1] as u32) << 8)
                | ((mac[2] as u32) << 16)
                | ((mac[3] as u32) << 24);
            let rah = (mac[4] as u32) | ((mac[5] as u32) << 8) | (1 << 31); // AV bit
            write_mmio32(self.mmio_base, REG_RAL0, ral);
            write_mmio32(self.mmio_base, REG_RAH0, rah);
        }
    }

    /// Initializes the RX descriptor ring.
    ///
    /// # Safety
    /// `rx_phys` must be a valid DMA-accessible physical address.
    unsafe fn init_rx(&mut self, rx_phys: u64) -> Result<()> {
        // SAFETY: Programming RX ring registers per Intel spec §14.6.
        unsafe {
            write_mmio32(self.mmio_base, REG_RDBAL, rx_phys as u32);
            write_mmio32(self.mmio_base, REG_RDBAH, (rx_phys >> 32) as u32);
            let ring_bytes = (RING_SIZE * core::mem::size_of::<RxDesc>()) as u32;
            write_mmio32(self.mmio_base, REG_RDLEN, ring_bytes);
            write_mmio32(self.mmio_base, REG_RDH, 0);
            write_mmio32(self.mmio_base, REG_RDT, (RING_SIZE - 1) as u32);
            self.rx_head = 0;

            let rctl = RCTL_EN | RCTL_BAM | RCTL_BSIZE_2048 | RCTL_SECRC;
            write_mmio32(self.mmio_base, REG_RCTL, rctl);
        }
        Ok(())
    }

    /// Initializes the TX descriptor ring.
    ///
    /// # Safety
    /// `tx_phys` must be a valid DMA-accessible physical address.
    unsafe fn init_tx(&mut self, tx_phys: u64) -> Result<()> {
        // SAFETY: Programming TX ring registers per Intel spec §14.7.
        unsafe {
            write_mmio32(self.mmio_base, REG_TDBAL, tx_phys as u32);
            write_mmio32(self.mmio_base, REG_TDBAH, (tx_phys >> 32) as u32);
            let ring_bytes = (RING_SIZE * core::mem::size_of::<TxDesc>()) as u32;
            write_mmio32(self.mmio_base, REG_TDLEN, ring_bytes);
            write_mmio32(self.mmio_base, REG_TDH, 0);
            write_mmio32(self.mmio_base, REG_TDT, 0);
            self.tx_tail = 0;

            // Standard inter-packet gap for 1 Gbps
            write_mmio32(self.mmio_base, REG_TIPG, 0x0060200A);

            let tctl = TCTL_EN | TCTL_PSP | TCTL_CT_1GBPS | TCTL_COLD_1GBPS;
            write_mmio32(self.mmio_base, REG_TCTL, tctl);
        }
        Ok(())
    }

    /// Updates the TX ring tail to submit a packet.
    ///
    /// # Parameters
    /// - `tx_ring`: Mutable reference to the TX descriptor ring.
    /// - `buf_phys`: Physical address of the packet buffer.
    /// - `len`: Packet length in bytes.
    ///
    /// # Safety
    /// TX ring must have been initialized. `buf_phys`/`len` must describe a valid buffer.
    pub unsafe fn send_packet(
        &mut self,
        tx_ring: &mut [TxDesc; RING_SIZE],
        buf_phys: u64,
        len: u16,
    ) -> Result<()> {
        let idx = self.tx_tail;
        // SAFETY: Checking DD bit to ensure slot is free.
        unsafe {
            if tx_ring[idx].status & TX_STATUS_DD == 0 && tx_ring[idx].cmd != 0 {
                return Err(Error::Busy);
            }
            tx_ring[idx].addr = buf_phys;
            tx_ring[idx].length = len;
            tx_ring[idx].cso = 0;
            tx_ring[idx].cmd = TX_CMD_EOP | TX_CMD_IFCS | TX_CMD_RS;
            tx_ring[idx].status = 0;
            tx_ring[idx].css = 0;
            tx_ring[idx].special = 0;

            self.tx_tail = (idx + 1) % RING_SIZE;
            write_mmio32(self.mmio_base, REG_TDT, self.tx_tail as u32);
        }
        Ok(())
    }

    /// Receives a packet from the RX ring if one is available.
    ///
    /// # Parameters
    /// - `rx_ring`: Reference to the RX descriptor ring.
    ///
    /// Returns the descriptor index and packet length, or `None` if no packet is ready.
    ///
    /// # Safety
    /// RX ring must have been initialized and all buffers programmed.
    pub unsafe fn recv_packet(&mut self, rx_ring: &[RxDesc; RING_SIZE]) -> Option<(usize, u16)> {
        let idx = self.rx_head;
        if rx_ring[idx].status & RX_STATUS_DD != 0 {
            let len = rx_ring[idx].length;
            let slot = idx;
            self.rx_head = (idx + 1) % RING_SIZE;
            Some((slot, len))
        } else {
            None
        }
    }

    /// Recycles RX descriptor at `idx` back to hardware.
    ///
    /// # Safety
    /// `idx` must be a valid ring index; descriptor's buffer must have been refilled.
    pub unsafe fn recycle_rx(&self, idx: usize) {
        // SAFETY: Writing RDT to give the descriptor back to hardware.
        unsafe { write_mmio32(self.mmio_base, REG_RDT, idx as u32) }
    }

    /// Returns `true` if the link is up.
    ///
    /// # Safety
    /// MMIO must be mapped.
    pub unsafe fn link_status(&self) -> bool {
        // SAFETY: Reading STATUS register.
        unsafe { read_mmio32(self.mmio_base, REG_STATUS) & STATUS_LU != 0 }
    }

    /// Reads and clears the Interrupt Cause Register.
    ///
    /// # Safety
    /// Must be called from the interrupt handler.
    pub unsafe fn handle_interrupt(&self) -> u32 {
        // SAFETY: Reading ICR clears all pending interrupt causes.
        unsafe { read_mmio32(self.mmio_base, REG_ICR) }
    }
}

// ---------------------------------------------------------------------------
// Device Registry
// ---------------------------------------------------------------------------

/// Registry of discovered e1000e controllers.
pub struct E1000eRegistry {
    devices: [Option<E1000e>; MAX_CONTROLLERS],
    count: usize,
}

impl E1000eRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [const { None }; MAX_CONTROLLERS],
            count: 0,
        }
    }

    /// Registers a new e1000e device.
    pub fn register(&mut self, dev: E1000e) -> Result<usize> {
        if self.count >= MAX_CONTROLLERS {
            return Err(Error::InvalidArgument);
        }
        let idx = self.count;
        self.devices[idx] = Some(dev);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a mutable reference to device at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut E1000e> {
        self.devices[index].as_mut()
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for E1000eRegistry {
    fn default() -> Self {
        Self::new()
    }
}
