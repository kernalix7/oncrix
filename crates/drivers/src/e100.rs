// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Intel PRO/100 (e100) Fast Ethernet driver.
//!
//! Supports the Intel 8255x family of Fast Ethernet controllers,
//! including the 82557, 82558, 82559, and 82550 chipsets commonly
//! found in older desktop and server hardware.

use oncrix_lib::{Error, Result};

/// PCI vendor/device identifiers for the e100 family.
pub const E100_VENDOR_ID: u16 = 0x8086;
pub const E100_DEVICE_82557: u16 = 0x1229;
pub const E100_DEVICE_82558: u16 = 0x1229; // Same PCI ID, different revision
pub const E100_DEVICE_82559: u16 = 0x1229;
pub const E100_DEVICE_82550: u16 = 0x1209;

/// CSR (Control/Status Register) offsets.
const CSR_SCB_STATUS: u32 = 0x00;
const CSR_SCB_CMD: u32 = 0x02;
const CSR_SCB_GEN_PTR: u32 = 0x04;
const CSR_PORT: u32 = 0x08;
const CSR_EEPROM_CTRL: u32 = 0x0E;
const CSR_MDI_CTRL: u32 = 0x10;

/// SCB (System Control Block) status word bits.
const SCB_STATUS_CX: u16 = 1 << 15; // CU command done
const SCB_STATUS_FR: u16 = 1 << 14; // Frame received
const SCB_STATUS_CNA: u16 = 1 << 13; // CU not active
const SCB_STATUS_RNR: u16 = 1 << 12; // RU not ready

/// SCB command word bits.
const SCB_CMD_CU_START: u16 = 0x0010;
const SCB_CMD_CU_RESUME: u16 = 0x0020;
const SCB_CMD_RU_START: u16 = 0x0001;
const SCB_CMD_RU_RESUME: u16 = 0x0002;

/// PORT command values.
const PORT_SOFTWARE_RESET: u32 = 0x0000_0000;
const PORT_SELF_TEST: u32 = 0x0000_0001;
const PORT_SELECTIVE_RESET: u32 = 0x0000_0002;
const PORT_DUMP: u32 = 0x0000_0003;

/// Maximum number of TX/RX descriptors.
const TX_RING_SIZE: usize = 64;
const RX_RING_SIZE: usize = 64;
const MAX_FRAME_SIZE: usize = 1514;

/// Command Block (CB) status bits.
const CB_STATUS_OK: u16 = 1 << 13;
const CB_STATUS_COMPLETE: u16 = 1 << 15;

/// Command Block commands.
const CB_CMD_NOP: u16 = 0x0000;
const CB_CMD_IA_SETUP: u16 = 0x0001;
const CB_CMD_CONFIG: u16 = 0x0002;
const CB_CMD_TRANSMIT: u16 = 0x0004;

/// CB link field end-of-list marker.
const CB_EL_BIT: u16 = 1 << 15;
const CB_S_BIT: u16 = 1 << 14;

/// Receive Frame Descriptor (RFD) status bits.
const RFD_STATUS_OK: u16 = 1 << 13;
const RFD_STATUS_COMPLETE: u16 = 1 << 15;

/// RFD end-of-list and suspend bits.
const RFD_EL_BIT: u16 = 1 << 15;
const RFD_S_BIT: u16 = 1 << 14;

/// Transmit Command Block in `#[repr(C)]` for DMA.
#[repr(C)]
pub struct TxCommandBlock {
    /// CB status word.
    pub status: u16,
    /// CB command word.
    pub command: u16,
    /// Link to next CB (physical address).
    pub link: u32,
    /// TBD array address.
    pub tbd_array: u32,
    /// Byte count in CB.
    pub byte_count: u16,
    /// Threshold for auto-transmit (1/8 units).
    pub threshold: u8,
    /// Number of TBDs (0 = simplified).
    pub tbd_count: u8,
    /// Inline frame data.
    pub data: [u8; MAX_FRAME_SIZE],
}

impl TxCommandBlock {
    /// Create a new zeroed transmit command block.
    pub const fn new() -> Self {
        Self {
            status: 0,
            command: 0,
            link: 0,
            tbd_array: 0xFFFF_FFFF,
            byte_count: 0,
            threshold: 0xE8,
            tbd_count: 0,
            data: [0u8; MAX_FRAME_SIZE],
        }
    }
}

impl Default for TxCommandBlock {
    fn default() -> Self {
        Self::new()
    }
}

/// Receive Frame Descriptor in `#[repr(C)]` for DMA.
#[repr(C)]
pub struct RxFrameDescriptor {
    /// RFD status word.
    pub status: u16,
    /// RFD command/control word.
    pub command: u16,
    /// Link to next RFD (physical address).
    pub link: u32,
    /// Reserved.
    pub reserved: u32,
    /// Actual count / receive buffer size.
    pub size: u16,
    /// Frame byte count.
    pub count: u16,
    /// Inline receive data.
    pub data: [u8; MAX_FRAME_SIZE],
}

impl RxFrameDescriptor {
    /// Create a new zeroed receive frame descriptor.
    pub const fn new() -> Self {
        Self {
            status: 0,
            command: RFD_EL_BIT | RFD_S_BIT,
            link: 0,
            reserved: 0,
            size: MAX_FRAME_SIZE as u16,
            count: 0,
            data: [0u8; MAX_FRAME_SIZE],
        }
    }
}

impl Default for RxFrameDescriptor {
    fn default() -> Self {
        Self::new()
    }
}

/// MAC address (6 bytes).
#[derive(Clone, Copy, Debug)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    /// Broadcast address.
    pub const BROADCAST: MacAddress = MacAddress([0xFF; 6]);

    /// Null/zero address.
    pub const ZERO: MacAddress = MacAddress([0u8; 6]);
}

/// Driver state for the Intel e100 NIC.
pub struct E100Driver {
    /// Base address of the MMIO CSR region.
    mmio_base: usize,
    /// Base I/O port (if using PIO mode).
    io_base: u16,
    /// Whether to use MMIO (true) or PIO (false).
    use_mmio: bool,
    /// MAC address read from EEPROM.
    mac_address: MacAddress,
    /// TX ring write index.
    tx_head: usize,
    /// TX ring read index.
    tx_tail: usize,
    /// RX ring current index.
    rx_head: usize,
    /// Driver is running.
    running: bool,
}

impl E100Driver {
    /// Create a new e100 driver instance.
    ///
    /// # Arguments
    /// - `mmio_base`: physical address of the CSR MMIO region
    /// - `io_base`: base PIO port (used as fallback)
    pub fn new(mmio_base: usize, io_base: u16) -> Self {
        Self {
            mmio_base,
            io_base,
            use_mmio: mmio_base != 0,
            mac_address: MacAddress::ZERO,
            tx_head: 0,
            tx_tail: 0,
            rx_head: 0,
            running: false,
        }
    }

    /// Initialize the e100 controller.
    pub fn init(&mut self) -> Result<()> {
        self.software_reset()?;
        self.self_test()?;
        self.read_mac_from_eeprom()?;
        self.configure()?;
        self.setup_ia()?;
        self.running = true;
        Ok(())
    }

    /// Issue a software reset via the PORT register.
    fn software_reset(&mut self) -> Result<()> {
        self.write_csr32(CSR_PORT, PORT_SOFTWARE_RESET);
        // Wait for reset to complete (at least 10 µs in real hardware).
        for _ in 0..100_000 {
            core::hint::spin_loop();
        }
        Ok(())
    }

    /// Issue a self-test command via the PORT register.
    fn self_test(&mut self) -> Result<()> {
        self.write_csr32(CSR_PORT, PORT_SELF_TEST);
        Ok(())
    }

    /// Read the MAC address from the serial EEPROM (93C46/93C56).
    fn read_mac_from_eeprom(&mut self) -> Result<()> {
        let mut mac = [0u8; 6];
        for (i, pair) in mac.chunks_mut(2).enumerate() {
            let word = self.eeprom_read(i as u8)?;
            pair[0] = (word & 0xFF) as u8;
            pair[1] = ((word >> 8) & 0xFF) as u8;
        }
        self.mac_address = MacAddress(mac);
        Ok(())
    }

    /// Read one 16-bit word from the serial EEPROM at address `addr`.
    fn eeprom_read(&self, addr: u8) -> Result<u16> {
        // Build the read command: 110 (read) followed by address bits.
        let cmd_bits = (0x06u32 << 6) | (addr as u32);
        // Clock out command bits, then clock in data bits.
        // This is a simplified EEPROM bit-bang sequence.
        let eeprom_ctrl = self.read_csr16(CSR_EEPROM_CTRL as u32);
        // Toggle EECS/EESK/EEDI/EEDO lines (abstracted here).
        let _ = eeprom_ctrl;
        let _ = cmd_bits;
        // In a real driver this would bit-bang the EEPROM control register.
        // For now we return a placeholder value.
        let data: u16 = 0x0000;
        Ok(data)
    }

    /// Send the configure command to set up the MAC.
    fn configure(&mut self) -> Result<()> {
        // The configuration block is 22 bytes; simplified here.
        Ok(())
    }

    /// Send the Individual Address (IA) setup command.
    fn setup_ia(&mut self) -> Result<()> {
        Ok(())
    }

    /// Transmit a raw Ethernet frame.
    ///
    /// # Arguments
    /// - `frame`: raw Ethernet frame bytes (must include header, max 1514 bytes)
    pub fn transmit(&mut self, frame: &[u8]) -> Result<()> {
        if frame.len() > MAX_FRAME_SIZE {
            return Err(Error::InvalidArgument);
        }
        if !self.running {
            return Err(Error::IoError);
        }
        let next = (self.tx_head + 1) % TX_RING_SIZE;
        if next == self.tx_tail {
            return Err(Error::Busy);
        }
        self.tx_head = next;
        // Submit CB to hardware (real impl would DMA the frame).
        let _status = self.read_csr16(CSR_SCB_STATUS as u32);
        Ok(())
    }

    /// Poll for received frames; returns the number of frames processed.
    pub fn poll_rx(&mut self) -> usize {
        let _status = self.read_csr16(CSR_SCB_STATUS as u32);
        // In a real driver, walk the RFD ring and dispatch complete frames.
        0
    }

    /// Handle an interrupt from the hardware.
    ///
    /// Returns a bitmask of `SCB_STATUS_*` bits indicating what occurred.
    pub fn handle_interrupt(&mut self) -> u16 {
        let status = self.read_csr16(CSR_SCB_STATUS as u32);
        // Acknowledge all interrupt causes.
        self.write_csr8(CSR_SCB_STATUS as u32 + 1, ((status >> 8) & 0xFF) as u8);
        status
    }

    /// Return the MAC address of this adapter.
    pub fn mac_address(&self) -> MacAddress {
        self.mac_address
    }

    // --- MMIO/PIO helpers ---

    fn read_csr8(&self, offset: u32) -> u8 {
        if self.use_mmio {
            let addr = (self.mmio_base + offset as usize) as *const u8;
            // SAFETY: mmio_base is a valid MMIO region mapped by the driver framework;
            // offset is within the 64-byte CSR window; volatile read required for MMIO.
            unsafe { core::ptr::read_volatile(addr) }
        } else {
            // PIO fallback (x86 only).
            #[cfg(target_arch = "x86_64")]
            {
                let mut val: u8;
                // SAFETY: io_base is a valid PCI I/O port assigned by firmware/BIOS.
                unsafe {
                    core::arch::asm!(
                        "in al, dx",
                        in("dx") self.io_base + offset as u16,
                        out("al") val,
                        options(nomem, nostack)
                    );
                }
                val
            }
            #[cfg(not(target_arch = "x86_64"))]
            0
        }
    }

    fn read_csr16(&self, offset: u32) -> u16 {
        if self.use_mmio {
            let addr = (self.mmio_base + offset as usize) as *const u16;
            // SAFETY: Same as read_csr8 but for a 16-bit aligned MMIO register.
            unsafe { core::ptr::read_volatile(addr) }
        } else {
            #[cfg(target_arch = "x86_64")]
            {
                let mut val: u16;
                // SAFETY: io_base is a valid PCI I/O port.
                unsafe {
                    core::arch::asm!(
                        "in ax, dx",
                        in("dx") self.io_base + offset as u16,
                        out("ax") val,
                        options(nomem, nostack)
                    );
                }
                val
            }
            #[cfg(not(target_arch = "x86_64"))]
            0
        }
    }

    fn read_csr32(&self, offset: u32) -> u32 {
        if self.use_mmio {
            let addr = (self.mmio_base + offset as usize) as *const u32;
            // SAFETY: Same as read_csr8 but for a 32-bit aligned MMIO register.
            unsafe { core::ptr::read_volatile(addr) }
        } else {
            #[cfg(target_arch = "x86_64")]
            {
                let mut val: u32;
                // SAFETY: io_base is a valid PCI I/O port.
                unsafe {
                    core::arch::asm!(
                        "in eax, dx",
                        in("dx") self.io_base + offset as u16,
                        out("eax") val,
                        options(nomem, nostack)
                    );
                }
                val
            }
            #[cfg(not(target_arch = "x86_64"))]
            0
        }
    }

    fn write_csr8(&mut self, offset: u32, val: u8) {
        if self.use_mmio {
            let addr = (self.mmio_base + offset as usize) as *mut u8;
            // SAFETY: mmio_base is a valid MMIO region; volatile write required for MMIO.
            unsafe { core::ptr::write_volatile(addr, val) }
        } else {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: io_base is a valid PCI I/O port.
            unsafe {
                core::arch::asm!(
                    "out dx, al",
                    in("dx") self.io_base + offset as u16,
                    in("al") val,
                    options(nomem, nostack)
                );
            }
        }
    }

    fn write_csr32(&mut self, offset: u32, val: u32) {
        if self.use_mmio {
            let addr = (self.mmio_base + offset as usize) as *mut u32;
            // SAFETY: mmio_base is a valid MMIO region; volatile write required for MMIO.
            unsafe { core::ptr::write_volatile(addr, val) }
        } else {
            #[cfg(target_arch = "x86_64")]
            // SAFETY: io_base is a valid PCI I/O port.
            unsafe {
                core::arch::asm!(
                    "out dx, eax",
                    in("dx") self.io_base + offset as u16,
                    in("eax") val,
                    options(nomem, nostack)
                );
            }
        }
    }
}
