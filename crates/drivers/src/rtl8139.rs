// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Realtek RTL8139 10/100 Mbps Ethernet NIC driver.
//!
//! Implements a bare-metal driver for the RTL8139 Fast Ethernet
//! controller using x86 port I/O. Supports packet transmission
//! via four fixed TX descriptors, continuous receive buffer,
//! interrupt handling, and MAC address reading.
//!
//! # Architecture
//!
//! - **Port I/O registers** — command, TX/RX config, interrupt
//! - **TX descriptors** — 4 fixed 1536-byte buffers (round-robin)
//! - **RX buffer** — 8K + 16 + 1500 contiguous ring buffer
//! - **Interrupts** — ROK, TOK, RER, TER, RXOVW via ISR/IMR
//!
//! Reference: Realtek RTL8139 Programming Guide.

use oncrix_lib::{Error, Result};

// -----------------------------------------------------------------------
// I/O Port Register Offsets
// -----------------------------------------------------------------------

/// MAC address register byte 0.
const REG_IDR0: u16 = 0x00;
/// MAC address register byte 1.
const _REG_IDR1: u16 = 0x01;
/// MAC address register byte 2.
const _REG_IDR2: u16 = 0x02;
/// MAC address register byte 3.
const _REG_IDR3: u16 = 0x03;
/// MAC address register byte 4.
const _REG_IDR4: u16 = 0x04;
/// MAC address register byte 5.
const _REG_IDR5: u16 = 0x05;

/// Multicast address register 0.
const _REG_MAR0: u16 = 0x08;
/// Multicast address register 1.
const _REG_MAR1: u16 = 0x09;
/// Multicast address register 2.
const _REG_MAR2: u16 = 0x0A;
/// Multicast address register 3.
const _REG_MAR3: u16 = 0x0B;
/// Multicast address register 4.
const _REG_MAR4: u16 = 0x0C;
/// Multicast address register 5.
const _REG_MAR5: u16 = 0x0D;
/// Multicast address register 6.
const _REG_MAR6: u16 = 0x0E;
/// Multicast address register 7.
const _REG_MAR7: u16 = 0x0F;

/// Transmit Status of Descriptor 0.
const REG_TSD0: u16 = 0x10;
/// Transmit Status of Descriptor 1.
const _REG_TSD1: u16 = 0x14;
/// Transmit Status of Descriptor 2.
const _REG_TSD2: u16 = 0x18;
/// Transmit Status of Descriptor 3.
const _REG_TSD3: u16 = 0x1C;

/// Transmit Start Address of Descriptor 0.
const REG_TSAD0: u16 = 0x20;
/// Transmit Start Address of Descriptor 1.
const _REG_TSAD1: u16 = 0x24;
/// Transmit Start Address of Descriptor 2.
const _REG_TSAD2: u16 = 0x28;
/// Transmit Start Address of Descriptor 3.
const _REG_TSAD3: u16 = 0x2C;

/// Receive Buffer Start Address.
const REG_RBSTART: u16 = 0x30;

/// Command register.
const REG_CMD: u16 = 0x37;

/// Current Address of Packet Read (read pointer).
const REG_CAPR: u16 = 0x38;

/// Current Buffer Address (write pointer, read-only).
const _REG_CBR: u16 = 0x3A;

/// Interrupt Mask Register.
const REG_IMR: u16 = 0x3C;

/// Interrupt Status Register.
const REG_ISR: u16 = 0x3E;

/// Transmit Configuration Register.
const _REG_TCR: u16 = 0x40;

/// Receive Configuration Register.
const REG_RCR: u16 = 0x44;

/// Configuration Register 1.
const REG_CONFIG1: u16 = 0x52;

/// Media Status Register.
const REG_MSR: u16 = 0x58;

// -----------------------------------------------------------------------
// Interrupt Status bits (ISR / IMR)
// -----------------------------------------------------------------------

/// Receive OK — packet received without error.
const ISR_ROK: u16 = 1 << 0;

/// Transmit OK — packet transmitted without error.
const ISR_TOK: u16 = 1 << 1;

/// Receive Error.
const ISR_RER: u16 = 1 << 2;

/// Transmit Error.
const ISR_TER: u16 = 1 << 3;

/// RX Buffer Overflow.
const _ISR_RXOVW: u16 = 1 << 4;

// -----------------------------------------------------------------------
// Receive Configuration Register flags
// -----------------------------------------------------------------------

/// Accept All Packets (promiscuous).
const _RCR_AAP: u32 = 1 << 0;

/// Accept Physical Match (unicast).
const RCR_APM: u32 = 1 << 1;

/// Accept Multicast.
const RCR_AM: u32 = 1 << 2;

/// Accept Broadcast.
const RCR_AB: u32 = 1 << 3;

/// Wrap bit — allow RX buffer to wrap around.
const RCR_WRAP: u32 = 1 << 7;

// -----------------------------------------------------------------------
// Command register bits
// -----------------------------------------------------------------------

/// Software Reset.
const CMD_RST: u8 = 1 << 4;

/// Receiver Enable.
const CMD_RE: u8 = 1 << 3;

/// Transmitter Enable.
const CMD_TE: u8 = 1 << 2;

// -----------------------------------------------------------------------
// Buffer and descriptor constants
// -----------------------------------------------------------------------

/// Number of TX descriptors (RTL8139 has exactly 4).
pub const TX_DESC_COUNT: usize = 4;

/// RX buffer size: 8192 + 16 header + 1500 wrap margin.
pub const RX_BUF_SIZE: usize = 8192 + 16 + 1500;

/// Maximum single TX packet size.
const MAX_TX_SIZE: usize = 1536;

/// Maximum number of RTL8139 devices in the registry.
pub const MAX_RTL8139_DEVICES: usize = 4;

/// MSR Link Status bit (active low — 0 means link up).
const MSR_LINK: u8 = 1 << 2;

// -----------------------------------------------------------------------
// Port I/O helpers
// -----------------------------------------------------------------------

/// Read an 8-bit value from an x86 I/O port.
///
/// # Safety
///
/// The caller must ensure that reading from `port` is valid and
/// does not cause undefined hardware behavior.
fn port_inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Caller guarantees `port` is a valid I/O port.
    // Uses `in al, dx` to read one byte from the port.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Read a 16-bit value from an x86 I/O port.
///
/// # Safety
///
/// The caller must ensure that reading from `port` is valid and
/// the port address is 16-bit aligned.
fn port_inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: Caller guarantees `port` is a valid, aligned
    // I/O port. Uses `in ax, dx` to read two bytes.
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            out("ax") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Read a 32-bit value from an x86 I/O port.
///
/// # Safety
///
/// The caller must ensure that reading from `port` is valid and
/// the port address is 32-bit aligned.
fn port_inl(port: u16) -> u32 {
    let val: u32;
    // SAFETY: Caller guarantees `port` is a valid, aligned
    // I/O port. Uses `in eax, dx` to read four bytes.
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            out("eax") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Write an 8-bit value to an x86 I/O port.
///
/// # Safety
///
/// The caller must ensure that writing to `port` is valid and
/// does not cause undefined hardware behavior.
fn port_outb(port: u16, val: u8) {
    // SAFETY: Caller guarantees `port` is a valid I/O port.
    // Uses `out dx, al` to write one byte to the port.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Write a 16-bit value to an x86 I/O port.
///
/// # Safety
///
/// The caller must ensure that writing to `port` is valid and
/// the port address is 16-bit aligned.
fn port_outw(port: u16, val: u16) {
    // SAFETY: Caller guarantees `port` is a valid, aligned
    // I/O port. Uses `out dx, ax` to write two bytes.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Write a 32-bit value to an x86 I/O port.
///
/// # Safety
///
/// The caller must ensure that writing to `port` is valid and
/// the port address is 32-bit aligned.
fn port_outl(port: u16, val: u32) {
    // SAFETY: Caller guarantees `port` is a valid, aligned
    // I/O port. Uses `out dx, eax` to write four bytes.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") val,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// -----------------------------------------------------------------------
// TX Descriptor
// -----------------------------------------------------------------------

/// RTL8139 transmit descriptor.
///
/// The RTL8139 has exactly 4 fixed TX descriptor slots, each with
/// its own TSD/TSAD register pair. This struct holds the buffer
/// and metadata for one slot.
pub struct TxDescriptor {
    /// Transmit buffer (max 1536 bytes).
    pub buffer: [u8; MAX_TX_SIZE],
    /// Length of data currently in the buffer.
    pub length: u16,
    /// Hardware status from the TSD register.
    pub status: u32,
    /// Whether this descriptor is in use.
    pub active: bool,
}

impl TxDescriptor {
    /// Create an empty transmit descriptor.
    const fn new() -> Self {
        Self {
            buffer: [0u8; MAX_TX_SIZE],
            length: 0,
            status: 0,
            active: false,
        }
    }
}

/// Const-initializable empty TX descriptor.
const EMPTY_TX_DESC: TxDescriptor = TxDescriptor::new();

// -----------------------------------------------------------------------
// RTL8139 Device
// -----------------------------------------------------------------------

/// Realtek RTL8139 10/100 Mbps Ethernet NIC driver.
///
/// Manages a single RTL8139 NIC through x86 port I/O registers.
/// Provides transmit and receive functionality via four fixed TX
/// descriptors and a continuous RX ring buffer.
///
/// # Usage
///
/// ```ignore
/// let mut nic = Rtl8139Device::new(io_base_port);
/// nic.init()?;
/// nic.send(&ethernet_frame)?;
/// ```
pub struct Rtl8139Device {
    /// I/O port base address.
    io_base: u16,
    /// Device MAC address (read during init).
    mac_address: [u8; 6],
    /// Receive ring buffer (8K + 16 + 1500 + padding).
    rx_buffer: [u8; RX_BUF_SIZE],
    /// Current read offset in the RX buffer.
    rx_offset: usize,
    /// Four fixed transmit descriptors.
    tx_descs: [TxDescriptor; TX_DESC_COUNT],
    /// Index of the next TX descriptor to use (0-3).
    current_tx: usize,
    /// Whether the physical link is up.
    link_up: bool,
    /// Whether the device has been initialized.
    initialized: bool,
}

impl Rtl8139Device {
    /// Create a new RTL8139 driver for a device at `io_base`.
    ///
    /// The device is not usable until [`init`](Self::init) is
    /// called.
    pub const fn new(io_base: u16) -> Self {
        Self {
            io_base,
            mac_address: [0u8; 6],
            rx_buffer: [0u8; RX_BUF_SIZE],
            rx_offset: 0,
            tx_descs: [EMPTY_TX_DESC; TX_DESC_COUNT],
            current_tx: 0,
            link_up: false,
            initialized: false,
        }
    }

    /// Initialize the RTL8139 device.
    ///
    /// Performs the following steps:
    /// 1. Power on via CONFIG1
    /// 2. Software reset via CMD register
    /// 3. Set up RX buffer address
    /// 4. Enable TX and RX
    /// 5. Configure RCR (accept unicast, multicast, broadcast)
    /// 6. Read MAC address
    /// 7. Enable interrupts (ROK, TOK, RER, TER)
    /// 8. Check link status
    pub fn init(&mut self) -> Result<()> {
        // Step 1: Power on the device.
        self.write_reg8(REG_CONFIG1, 0x00);

        // Step 2: Software reset.
        self.write_reg8(REG_CMD, CMD_RST);

        // Wait for reset to complete (RST bit self-clears).
        let mut timeout = 1_000_000u32;
        while self.read_reg8(REG_CMD) & CMD_RST != 0 {
            timeout = timeout.saturating_sub(1);
            if timeout == 0 {
                return Err(Error::IoError);
            }
        }

        // Step 3: Set the RX buffer physical address.
        let rx_addr = self.rx_buffer.as_ptr() as u32;
        self.write_reg32(REG_RBSTART, rx_addr);

        // Step 4: Enable transmitter and receiver.
        self.write_reg8(REG_CMD, CMD_RE | CMD_TE);

        // Step 5: Configure RCR — accept physical, multicast,
        // broadcast, and wrap at buffer end.
        self.write_reg32(REG_RCR, RCR_APM | RCR_AM | RCR_AB | RCR_WRAP);

        // Step 6: Read MAC address from IDR0-IDR5.
        self.mac_address = self.read_mac();

        // Step 7: Enable interrupts for RX/TX OK and errors.
        self.write_reg16(REG_IMR, ISR_ROK | ISR_TOK | ISR_RER | ISR_TER);

        // Step 8: Check link status.
        self.link_up = self.link_status();

        self.initialized = true;
        Ok(())
    }

    /// Read an 8-bit register at `offset` from the I/O base.
    pub fn read_reg8(&self, offset: u16) -> u8 {
        port_inb(self.io_base + offset)
    }

    /// Read a 16-bit register at `offset` from the I/O base.
    pub fn read_reg16(&self, offset: u16) -> u16 {
        port_inw(self.io_base + offset)
    }

    /// Read a 32-bit register at `offset` from the I/O base.
    pub fn read_reg32(&self, offset: u16) -> u32 {
        port_inl(self.io_base + offset)
    }

    /// Write an 8-bit value to a register at `offset`.
    pub fn write_reg8(&self, offset: u16, val: u8) {
        port_outb(self.io_base + offset, val);
    }

    /// Write a 16-bit value to a register at `offset`.
    pub fn write_reg16(&self, offset: u16, val: u16) {
        port_outw(self.io_base + offset, val);
    }

    /// Write a 32-bit value to a register at `offset`.
    pub fn write_reg32(&self, offset: u16, val: u32) {
        port_outl(self.io_base + offset, val);
    }

    /// Read the 6-byte MAC address from IDR0-IDR5.
    pub fn read_mac(&self) -> [u8; 6] {
        let mut mac = [0u8; 6];
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = self.read_reg8(REG_IDR0 + i as u16);
        }
        mac
    }

    /// Transmit an Ethernet frame.
    ///
    /// Copies `data` into the next available TX descriptor buffer,
    /// writes the TSAD (buffer address) and TSD (status + length)
    /// registers, and advances to the next descriptor.
    ///
    /// Returns an error if the device is not initialized, the
    /// packet is empty, exceeds the maximum TX size, or the
    /// current descriptor is still active.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if data.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if data.len() > MAX_TX_SIZE {
            return Err(Error::InvalidArgument);
        }

        let idx = self.current_tx;

        if self.tx_descs[idx].active {
            return Err(Error::WouldBlock);
        }

        // Copy packet data into the TX descriptor buffer.
        self.tx_descs[idx].buffer[..data.len()].copy_from_slice(data);
        self.tx_descs[idx].length = data.len() as u16;
        self.tx_descs[idx].active = true;

        // Write the buffer physical address to TSAD[idx].
        let tsad_offset = REG_TSAD0 + (idx as u16) * 4;
        let buf_addr = self.tx_descs[idx].buffer.as_ptr() as u32;
        self.write_reg32(tsad_offset, buf_addr);

        // Write length to TSD[idx] to start transmission.
        // Bits 0-12 = size, bit 13 = OWN (cleared to give HW).
        let tsd_offset = REG_TSD0 + (idx as u16) * 4;
        self.write_reg32(tsd_offset, data.len() as u32);

        // Advance to the next TX descriptor (round-robin).
        self.current_tx = (idx + 1) % TX_DESC_COUNT;

        Ok(())
    }

    /// Poll for a received packet.
    ///
    /// Checks the RX buffer at the current read offset for a
    /// completed packet header. The RTL8139 prepends a 4-byte
    /// header (status + length) before each packet.
    ///
    /// Returns `Some((offset_in_rx_buf, length))` pointing to
    /// the packet data (after the 4-byte header), or `None` if
    /// no packet is ready.
    pub fn receive(&mut self) -> Option<(usize, usize)> {
        if !self.initialized {
            return None;
        }

        // Check if the RX buffer is empty (CMD bit 0 = BUFE).
        let cmd = self.read_reg8(REG_CMD);
        if cmd & 0x01 != 0 {
            return None;
        }

        let offset = self.rx_offset;

        // Read the 4-byte packet header from the RX buffer.
        // Bytes 0-1: status, Bytes 2-3: length (incl. CRC).
        let status = u16::from_le_bytes([self.rx_buffer[offset], self.rx_buffer[offset + 1]]);

        // Check ROK bit in the packet header status.
        if status & 0x0001 == 0 {
            return None;
        }

        let length =
            u16::from_le_bytes([self.rx_buffer[offset + 2], self.rx_buffer[offset + 3]]) as usize;

        // Data starts after the 4-byte header.
        let data_offset = offset + 4;

        // Advance rx_offset: header(4) + length, aligned to
        // 4-byte boundary, wrapped within 8K.
        let next = (offset + 4 + length + 3) & !3;
        self.rx_offset = next % 8192;

        // Update CAPR (read pointer) for the hardware.
        // CAPR = rx_offset - 16 (hardware quirk).
        let capr = (self.rx_offset as u16).wrapping_sub(16);
        self.write_reg16(REG_CAPR, capr);

        Some((data_offset, length))
    }

    /// Handle an RTL8139 interrupt.
    ///
    /// Reads the ISR register, acknowledges all pending
    /// interrupts by writing back the same value, and returns
    /// the raw status bits. The caller inspects the bits to
    /// determine the cause (ROK, TOK, RER, TER, RXOVW).
    pub fn handle_interrupt(&mut self) -> u16 {
        let isr = self.read_reg16(REG_ISR);

        // Acknowledge all pending interrupts.
        self.write_reg16(REG_ISR, isr);

        // Mark completed TX descriptors as inactive.
        if isr & ISR_TOK != 0 {
            for i in 0..TX_DESC_COUNT {
                if self.tx_descs[i].active {
                    let tsd_offset = REG_TSD0 + (i as u16) * 4;
                    let tsd = self.read_reg32(tsd_offset);
                    // Bit 15 = TOK in TSD register.
                    if tsd & (1 << 15) != 0 {
                        self.tx_descs[i].active = false;
                        self.tx_descs[i].status = tsd;
                    }
                }
            }
        }

        // Update link status.
        self.link_up = self.link_status();

        isr
    }

    /// Check whether the physical link is up.
    ///
    /// Reads the Media Status Register. The link bit is active
    /// low: 0 means link is up, 1 means link is down.
    pub fn link_status(&self) -> bool {
        self.read_reg8(REG_MSR) & MSR_LINK == 0
    }

    /// Return a reference to the device's MAC address.
    pub fn mac_address(&self) -> &[u8; 6] {
        &self.mac_address
    }
}

impl core::fmt::Debug for Rtl8139Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8139Device")
            .field("io_base", &self.io_base)
            .field("mac_address", &self.mac_address)
            .field("link_up", &self.link_up)
            .field("initialized", &self.initialized)
            .field("rx_offset", &self.rx_offset)
            .field("current_tx", &self.current_tx)
            .finish()
    }
}

// -----------------------------------------------------------------------
// RTL8139 Registry
// -----------------------------------------------------------------------

/// Registry for tracking multiple RTL8139 devices.
///
/// Supports up to [`MAX_RTL8139_DEVICES`] concurrently registered
/// devices, identified by their I/O port base address.
pub struct Rtl8139Registry {
    /// Registered I/O base addresses (`0` means empty slot).
    bases: [u16; MAX_RTL8139_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for Rtl8139Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Rtl8139Registry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            bases: [0; MAX_RTL8139_DEVICES],
            count: 0,
        }
    }

    /// Register a new RTL8139 device by its I/O base address.
    ///
    /// Returns an error if the registry is full, the address is
    /// zero, or the device is already registered.
    pub fn register(&mut self, io_base: u16) -> Result<()> {
        if io_base == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.bases[..self.count].contains(&io_base) {
            return Err(Error::AlreadyExists);
        }
        if self.count >= MAX_RTL8139_DEVICES {
            return Err(Error::OutOfMemory);
        }
        self.bases[self.count] = io_base;
        self.count += 1;
        Ok(())
    }

    /// Return the I/O base address at the given index.
    ///
    /// Returns `None` if `index` is out of range.
    pub fn get(&self, index: usize) -> Option<u16> {
        if index < self.count {
            Some(self.bases[index])
        } else {
            None
        }
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the registry contains no devices.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl core::fmt::Debug for Rtl8139Registry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8139Registry")
            .field("count", &self.count)
            .field("bases", &&self.bases[..self.count])
            .finish()
    }
}
