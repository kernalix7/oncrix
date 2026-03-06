// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel e1000 Gigabit Ethernet NIC hardware registers and initialization.
//!
//! Implements the hardware-level register access layer for the Intel 8254x
//! (e1000) Gigabit Ethernet family. Covers register definitions, device
//! reset, link management, RX/TX ring setup, and interrupt control.
//!
//! # Register Map (MMIO, 128 KiB)
//!
//! | Offset  | Name   | Description                       |
//! |---------|--------|-----------------------------------|
//! | 0x0000  | CTRL   | Device Control                    |
//! | 0x0008  | STATUS | Device Status                     |
//! | 0x0014  | EECD   | EEPROM/Flash Control              |
//! | 0x0018  | EERD   | EEPROM Read                       |
//! | 0x00C0  | ICR    | Interrupt Cause Read              |
//! | 0x00D0  | ICS    | Interrupt Cause Set               |
//! | 0x00D8  | IMS    | Interrupt Mask Set/Read           |
//! | 0x00DC  | IMC    | Interrupt Mask Clear              |
//! | 0x0100  | RCTL   | Receive Control                   |
//! | 0x0400  | TCTL   | Transmit Control                  |
//! | 0x2800  | RDBAL  | RX Descriptor Base Low            |
//! | 0x2804  | RDBAH  | RX Descriptor Base High           |
//! | 0x2808  | RDLEN  | RX Descriptor Length              |
//! | 0x2810  | RDH    | RX Descriptor Head                |
//! | 0x2818  | RDT    | RX Descriptor Tail                |
//! | 0x3800  | TDBAL  | TX Descriptor Base Low            |
//! | 0x3804  | TDBAH  | TX Descriptor Base High           |
//! | 0x3808  | TDLEN  | TX Descriptor Length              |
//! | 0x3810  | TDH    | TX Descriptor Head                |
//! | 0x3818  | TDT    | TX Descriptor Tail                |
//! | 0x5400  | RAL0   | Receive Address Low               |
//! | 0x5404  | RAH0   | Receive Address High              |
//!
//! Reference: Intel 8254x Family of Gigabit Ethernet Controllers Software
//! Developer's Manual.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Register Offsets
// ---------------------------------------------------------------------------

/// Device Control Register.
pub const E1000_CTRL: u32 = 0x0000;
/// Device Status Register.
pub const E1000_STATUS: u32 = 0x0008;
/// EEPROM Control Register.
pub const _E1000_EECD: u32 = 0x0014;
/// EEPROM Read Register.
pub const E1000_EERD: u32 = 0x0018;
/// Interrupt Cause Read.
pub const E1000_ICR: u32 = 0x00C0;
/// Interrupt Cause Set.
pub const _E1000_ICS: u32 = 0x00D0;
/// Interrupt Mask Set/Read.
pub const E1000_IMS: u32 = 0x00D8;
/// Interrupt Mask Clear.
pub const E1000_IMC: u32 = 0x00DC;
/// Receive Control.
pub const E1000_RCTL: u32 = 0x0100;
/// Transmit Control.
pub const E1000_TCTL: u32 = 0x0400;
/// Transmit IPG Register.
pub const E1000_TIPG: u32 = 0x0410;
/// RX Descriptor Base Low.
pub const E1000_RDBAL: u32 = 0x2800;
/// RX Descriptor Base High.
pub const E1000_RDBAH: u32 = 0x2804;
/// RX Descriptor Length.
pub const E1000_RDLEN: u32 = 0x2808;
/// RX Descriptor Head.
pub const E1000_RDH: u32 = 0x2810;
/// RX Descriptor Tail.
pub const E1000_RDT: u32 = 0x2818;
/// TX Descriptor Base Low.
pub const E1000_TDBAL: u32 = 0x3800;
/// TX Descriptor Base High.
pub const E1000_TDBAH: u32 = 0x3804;
/// TX Descriptor Length.
pub const E1000_TDLEN: u32 = 0x3808;
/// TX Descriptor Head.
pub const E1000_TDH: u32 = 0x3810;
/// TX Descriptor Tail.
pub const E1000_TDT: u32 = 0x3818;
/// Receive Address Low (entry 0).
pub const E1000_RAL0: u32 = 0x5400;
/// Receive Address High (entry 0).
pub const E1000_RAH0: u32 = 0x5404;
/// Multicast Table Array base.
pub const E1000_MTA: u32 = 0x5200;

// ---------------------------------------------------------------------------
// CTRL bit fields
// ---------------------------------------------------------------------------

/// CTRL: Full Duplex.
pub const CTRL_FD: u32 = 1 << 0;
/// CTRL: Link Reset.
pub const CTRL_LRST: u32 = 1 << 3;
/// CTRL: Auto-Speed Detection Enable.
pub const CTRL_ASDE: u32 = 1 << 5;
/// CTRL: Set Link Up.
pub const CTRL_SLU: u32 = 1 << 6;
/// CTRL: Speed 1000 Mbps ([9:8] = 10).
pub const CTRL_SPEED_1000: u32 = 0x2 << 8;
/// CTRL: Force Speed.
pub const CTRL_FRCSPD: u32 = 1 << 11;
/// CTRL: Force Duplex.
pub const CTRL_FRCDPX: u32 = 1 << 12;
/// CTRL: Software Reset.
pub const CTRL_RST: u32 = 1 << 26;
/// CTRL: PHY Reset.
pub const CTRL_PHY_RST: u32 = 1 << 31;

// ---------------------------------------------------------------------------
// STATUS bit fields
// ---------------------------------------------------------------------------

/// STATUS: Link Up.
pub const STATUS_LU: u32 = 1 << 1;
/// STATUS: Speed bits [7:6].
pub const STATUS_SPEED_MASK: u32 = 0x3 << 6;
/// STATUS: Speed 1000 Mbps.
pub const STATUS_SPEED_1000: u32 = 0x2 << 6;

// ---------------------------------------------------------------------------
// RCTL bit fields
// ---------------------------------------------------------------------------

/// RCTL: Receiver Enable.
pub const RCTL_EN: u32 = 1 << 1;
/// RCTL: Store Bad Packets.
pub const _RCTL_SBP: u32 = 1 << 2;
/// RCTL: Unicast Promiscuous.
pub const RCTL_UPE: u32 = 1 << 3;
/// RCTL: Multicast Promiscuous.
pub const RCTL_MPE: u32 = 1 << 4;
/// RCTL: Long Packet Enable.
pub const _RCTL_LPE: u32 = 1 << 5;
/// RCTL: Receive Buffer Size = 2048 B (BSIZE[9:8] = 00).
pub const RCTL_BSIZE_2048: u32 = 0;
/// RCTL: Strip Ethernet CRC.
pub const RCTL_SECRC: u32 = 1 << 26;

// ---------------------------------------------------------------------------
// TCTL bit fields
// ---------------------------------------------------------------------------

/// TCTL: Transmit Enable.
pub const TCTL_EN: u32 = 1 << 1;
/// TCTL: Pad Short Packets.
pub const TCTL_PSP: u32 = 1 << 3;
/// TCTL: Collision Threshold (default 15).
pub const TCTL_CT_DEFAULT: u32 = 0x0F << 4;
/// TCTL: Collision Distance (default 63 for half-duplex).
pub const TCTL_COLD_DEFAULT: u32 = 0x3F << 12;

// ---------------------------------------------------------------------------
// ICR / IMS bit fields
// ---------------------------------------------------------------------------

/// ICR/IMS: TX Descriptor Written Back.
pub const ICR_TXDW: u32 = 1 << 0;
/// ICR/IMS: TX Queue Empty.
pub const ICR_TXQE: u32 = 1 << 1;
/// ICR/IMS: Link Status Change.
pub const ICR_LSC: u32 = 1 << 2;
/// ICR/IMS: RX Sequence Error.
pub const _ICR_RXSEQ: u32 = 1 << 3;
/// ICR/IMS: RX Descriptor Minimum Threshold.
pub const ICR_RXDMT0: u32 = 1 << 4;
/// ICR/IMS: RX Overrun.
pub const ICR_RXO: u32 = 1 << 6;
/// ICR/IMS: RX Timer Interrupt.
pub const ICR_RXT0: u32 = 1 << 7;

// ---------------------------------------------------------------------------
// EERD fields
// ---------------------------------------------------------------------------

/// EERD: Start read cycle.
pub const EERD_START: u32 = 1 << 0;
/// EERD: Read done.
pub const EERD_DONE: u32 = 1 << 4;
/// EERD: Address shift.
pub const EERD_ADDR_SHIFT: u32 = 8;
/// EERD: Data shift.
pub const EERD_DATA_SHIFT: u32 = 16;

/// EEPROM read timeout.
const EERD_TIMEOUT: u32 = 10_000;

// ---------------------------------------------------------------------------
// RX/TX Descriptor structures
// ---------------------------------------------------------------------------

/// RX legacy descriptor (16 bytes, `#[repr(C)]` for DMA).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RxDesc {
    /// Buffer physical address.
    pub buf_addr: u64,
    /// Packet length (filled by hardware on receive).
    pub length: u16,
    /// Checksum (filled by hardware).
    pub checksum: u16,
    /// Status bits (bit 0 = DD: descriptor done).
    pub status: u8,
    /// Error bits.
    pub errors: u8,
    /// Special field (VLAN tag).
    pub special: u16,
}

impl RxDesc {
    /// Checks if the Descriptor Done bit (DD) is set.
    pub fn is_done(&self) -> bool {
        self.status & 0x01 != 0
    }
    /// Checks if End of Packet bit (EOP) is set.
    pub fn is_eop(&self) -> bool {
        self.status & 0x02 != 0
    }
}

/// TX legacy descriptor (16 bytes, `#[repr(C)]` for DMA).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TxDesc {
    /// Buffer physical address.
    pub buf_addr: u64,
    /// Packet length in bytes.
    pub length: u16,
    /// Checksum Start field.
    pub cso: u8,
    /// Command byte: RS|IFCS|EOP.
    pub cmd: u8,
    /// Status byte (bit 0 = DD: descriptor done).
    pub status: u8,
    /// Checksum Offset.
    pub css: u8,
    /// Special / VLAN.
    pub special: u16,
}

impl TxDesc {
    /// Checks if the Descriptor Done bit is set (TX complete).
    pub fn is_done(&self) -> bool {
        self.status & 0x01 != 0
    }
}

/// TxDesc command: End of Packet.
pub const TX_CMD_EOP: u8 = 1 << 0;
/// TxDesc command: Insert FCS/CRC.
pub const TX_CMD_IFCS: u8 = 1 << 1;
/// TxDesc command: Report Status (set DD when done).
pub const TX_CMD_RS: u8 = 1 << 3;

// ---------------------------------------------------------------------------
// E1000Hw — hardware register accessor
// ---------------------------------------------------------------------------

/// Intel e1000 hardware register state.
pub struct E1000Hw {
    /// MMIO base address.
    mmio_base: u64,
    /// Whether the device has been initialized.
    initialized: bool,
    /// MAC address read from EEPROM.
    mac_addr: [u8; 6],
}

impl E1000Hw {
    /// Creates a new hardware accessor.
    pub const fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            initialized: false,
            mac_addr: [0u8; 6],
        }
    }

    /// Initializes the e1000: resets hardware, reads MAC, configures rings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `mmio_base` is zero.
    /// Returns [`Error::IoError`] if EEPROM read times out.
    pub fn init(&mut self) -> Result<()> {
        if self.mmio_base == 0 {
            return Err(Error::InvalidArgument);
        }
        // Disable interrupts.
        self.write(E1000_IMC, 0xFFFF_FFFF);

        // Reset the device.
        let ctrl = self.read(E1000_CTRL);
        self.write(E1000_CTRL, ctrl | CTRL_RST);
        // Wait for reset to complete (hardware clears RST bit).
        for _ in 0..10_000 {
            if self.read(E1000_CTRL) & CTRL_RST == 0 {
                break;
            }
        }

        // Disable interrupts again after reset.
        self.write(E1000_IMC, 0xFFFF_FFFF);

        // Read MAC from EEPROM.
        self.mac_addr = self.read_mac_eeprom()?;

        // Program receive address register with MAC.
        let ral = u32::from(self.mac_addr[0])
            | (u32::from(self.mac_addr[1]) << 8)
            | (u32::from(self.mac_addr[2]) << 16)
            | (u32::from(self.mac_addr[3]) << 24);
        let rah = u32::from(self.mac_addr[4]) | (u32::from(self.mac_addr[5]) << 8) | (1 << 31); // AV = address valid
        self.write(E1000_RAL0, ral);
        self.write(E1000_RAH0, rah);

        // Clear multicast table.
        for i in 0..128u32 {
            self.write(E1000_MTA + i * 4, 0);
        }

        // Set link up, auto-speed detection.
        let ctrl = self.read(E1000_CTRL);
        self.write(E1000_CTRL, (ctrl | CTRL_ASDE | CTRL_SLU) & !CTRL_LRST);

        self.initialized = true;
        Ok(())
    }

    /// Configures the RX ring descriptor base and length.
    pub fn setup_rx_ring(&self, base_phys: u64, len_bytes: u32) {
        self.write(E1000_RDBAL, (base_phys & 0xFFFF_FFFF) as u32);
        self.write(E1000_RDBAH, (base_phys >> 32) as u32);
        self.write(E1000_RDLEN, len_bytes);
        self.write(E1000_RDH, 0);
        self.write(E1000_RDT, 0);
    }

    /// Enables the RX engine.
    pub fn enable_rx(&self) {
        self.write(
            E1000_RCTL,
            RCTL_EN | RCTL_UPE | RCTL_MPE | RCTL_BSIZE_2048 | RCTL_SECRC,
        );
    }

    /// Configures the TX ring descriptor base and length.
    pub fn setup_tx_ring(&self, base_phys: u64, len_bytes: u32) {
        self.write(E1000_TDBAL, (base_phys & 0xFFFF_FFFF) as u32);
        self.write(E1000_TDBAH, (base_phys >> 32) as u32);
        self.write(E1000_TDLEN, len_bytes);
        self.write(E1000_TDH, 0);
        self.write(E1000_TDT, 0);
    }

    /// Enables the TX engine.
    pub fn enable_tx(&self) {
        // Standard TIPG for 1 Gbps.
        self.write(E1000_TIPG, 0x0060_200A);
        self.write(
            E1000_TCTL,
            TCTL_EN | TCTL_PSP | TCTL_CT_DEFAULT | TCTL_COLD_DEFAULT,
        );
    }

    /// Enables the specified interrupt sources.
    pub fn enable_interrupts(&self, mask: u32) {
        self.write(E1000_IMS, mask);
    }

    /// Disables all interrupts.
    pub fn disable_interrupts(&self) {
        self.write(E1000_IMC, 0xFFFF_FFFF);
    }

    /// Reads and clears the interrupt cause register.
    pub fn read_icr(&self) -> u32 {
        self.read(E1000_ICR)
    }

    /// Returns the RX tail register value.
    pub fn rx_tail(&self) -> u32 {
        self.read(E1000_RDT)
    }

    /// Writes the RX tail register.
    pub fn write_rx_tail(&self, tail: u32) {
        self.write(E1000_RDT, tail);
    }

    /// Returns the TX tail register value.
    pub fn tx_tail(&self) -> u32 {
        self.read(E1000_TDT)
    }

    /// Writes the TX tail register.
    pub fn write_tx_tail(&self, tail: u32) {
        self.write(E1000_TDT, tail);
    }

    /// Returns `true` if the link is up.
    pub fn is_link_up(&self) -> bool {
        self.read(E1000_STATUS) & STATUS_LU != 0
    }

    /// Returns the MAC address.
    pub fn mac_addr(&self) -> [u8; 6] {
        self.mac_addr
    }

    /// Returns `true` if the device is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -----------------------------------------------------------------------
    // EEPROM access
    // -----------------------------------------------------------------------

    fn read_eeprom_word(&self, offset: u8) -> Result<u16> {
        self.write(
            E1000_EERD,
            EERD_START | ((offset as u32) << EERD_ADDR_SHIFT),
        );
        for _ in 0..EERD_TIMEOUT {
            let val = self.read(E1000_EERD);
            if val & EERD_DONE != 0 {
                return Ok((val >> EERD_DATA_SHIFT) as u16);
            }
        }
        Err(Error::IoError)
    }

    fn read_mac_eeprom(&self) -> Result<[u8; 6]> {
        let mut mac = [0u8; 6];
        for i in 0..3u8 {
            let word = self.read_eeprom_word(i)?;
            mac[i as usize * 2] = (word & 0xFF) as u8;
            mac[i as usize * 2 + 1] = (word >> 8) as u8;
        }
        Ok(mac)
    }

    // -----------------------------------------------------------------------
    // MMIO helpers
    // -----------------------------------------------------------------------

    fn read(&self, offset: u32) -> u32 {
        let addr = (self.mmio_base + offset as u64) as *const u32;
        // SAFETY: mmio_base is a valid e1000 MMIO region; volatile read required.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write(&self, offset: u32, val: u32) {
        let addr = (self.mmio_base + offset as u64) as *mut u32;
        // SAFETY: mmio_base is a valid e1000 MMIO region; volatile write required.
        unsafe { core::ptr::write_volatile(addr, val) }
    }
}

impl Default for E1000Hw {
    fn default() -> Self {
        Self::new(0)
    }
}
