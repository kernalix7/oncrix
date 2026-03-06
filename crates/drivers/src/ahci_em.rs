// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AHCI Enclosure Management (EM) driver.
//!
//! Implements the AHCI 1.3.1 Enclosure Management interface for controlling
//! drive activity LEDs (SGPIO / SES-2 / IBPI) connected to a SATA HBA.
//! Enclosure management is used in server/NAS chassis to indicate drive status
//! through LED patterns.

use oncrix_lib::{Error, Result};

/// Maximum number of EM ports (slot index 0-based).
pub const EM_MAX_PORTS: usize = 32;

/// Enclosure Management (EM) message types (AHCI 10.27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EmMessageType {
    /// LED message.
    Led = 0,
    /// SAF-TE enclosure management.
    SafTe = 1,
    /// SES-2 enclosure management.
    Ses2 = 2,
    /// SGPIO enclosure management.
    Sgpio = 3,
}

/// LED message (AHCI LED Message Type).
///
/// Each port carries a 32-bit message with activity/locate/fault bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct LedMessage {
    /// HBA port number.
    pub port: u8,
    /// Activity LED state.
    pub activity: bool,
    /// Locate LED state (blue blink to find the drive).
    pub locate: bool,
    /// Fault LED state (amber).
    pub fault: bool,
}

impl LedMessage {
    /// Encodes the LED message into a 32-bit EM message payload.
    ///
    /// Format per AHCI spec Table 75: [31:24]=reserved, [19]=fault,
    /// [18]=locate, [17]=activity, [15:8]=port, [7:0]=hba_port.
    pub fn encode(&self) -> u32 {
        let mut val: u32 = self.port as u32;
        val |= (self.port as u32) << 8;
        if self.activity {
            val |= 1 << 17;
        }
        if self.locate {
            val |= 1 << 18;
        }
        if self.fault {
            val |= 1 << 19;
        }
        val
    }

    /// Decodes a 32-bit EM payload into an LED message.
    pub fn decode(val: u32) -> Self {
        Self {
            port: (val & 0xFF) as u8,
            activity: (val & (1 << 17)) != 0,
            locate: (val & (1 << 18)) != 0,
            fault: (val & (1 << 19)) != 0,
        }
    }
}

/// AHCI EM control register offsets (from HBA MMIO base).
struct EmRegs;

impl EmRegs {
    /// EM Location register offset (points to EM buffer in HBA BAR).
    const EM_LOC: usize = 0x1C;
    /// EM Control register.
    const EM_CTL: usize = 0x20;

    // EM_CTL bits.
    const CTL_MR: u32 = 1 << 0; // Message Received (read-only).
    const CTL_TM: u32 = 1 << 8; // Transmit Message.
    const CTL_RST: u32 = 1 << 9; // Reset.
    const CTL_LED: u32 = 1 << 16; // LED message type supported.
}

/// AHCI Enclosure Management driver.
pub struct AhciEnclosureManager {
    /// HBA MMIO base.
    hba_base: usize,
    /// EM buffer physical offset within the HBA BAR (from EM_LOC).
    em_buf_offset: usize,
    /// EM buffer size in bytes.
    em_buf_size: usize,
    /// Supported message type (read from EM_CTL).
    supported_type: EmMessageType,
    /// Current LED state per port.
    led_state: [LedMessage; EM_MAX_PORTS],
}

impl AhciEnclosureManager {
    /// Creates a new EM driver for an HBA.
    ///
    /// # Arguments
    ///
    /// * `hba_base` — MMIO base of the HBA.
    pub const fn new(hba_base: usize) -> Self {
        Self {
            hba_base,
            em_buf_offset: 0,
            em_buf_size: 0,
            supported_type: EmMessageType::Led,
            led_state: [const {
                LedMessage {
                    port: 0,
                    activity: false,
                    locate: false,
                    fault: false,
                }
            }; EM_MAX_PORTS],
        }
    }

    /// Initialises the EM interface by reading EM_LOC and EM_CTL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the HBA does not support EM.
    pub fn init(&mut self) -> Result<()> {
        let ctl = self.read32(EmRegs::EM_CTL);
        if (ctl & EmRegs::CTL_LED) == 0 {
            return Err(Error::NotImplemented);
        }
        let loc = self.read32(EmRegs::EM_LOC);
        self.em_buf_size = ((loc >> 16) & 0xFF) as usize * 4;
        self.em_buf_offset = (loc & 0xFFFF) as usize * 4;
        // Reset EM controller.
        self.write32(EmRegs::EM_CTL, EmRegs::CTL_RST);
        Ok(())
    }

    /// Sets the LED state for `port`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if port >= EM_MAX_PORTS.
    /// Returns [`Error::Busy`] if the EM transmitter is busy.
    pub fn set_led(
        &mut self,
        port: usize,
        activity: bool,
        locate: bool,
        fault: bool,
    ) -> Result<()> {
        if port >= EM_MAX_PORTS {
            return Err(Error::InvalidArgument);
        }
        let msg = LedMessage {
            port: port as u8,
            activity,
            locate,
            fault,
        };
        self.led_state[port] = msg;
        self.transmit_led(msg)
    }

    /// Clears all LEDs on all ports.
    pub fn clear_all(&mut self) -> Result<()> {
        for i in 0..EM_MAX_PORTS {
            let msg = LedMessage {
                port: i as u8,
                activity: false,
                locate: false,
                fault: false,
            };
            self.led_state[i] = msg;
            self.transmit_led(msg)?;
        }
        Ok(())
    }

    /// Returns the current LED state for `port`.
    pub fn led_state(&self, port: usize) -> Option<&LedMessage> {
        if port >= EM_MAX_PORTS {
            return None;
        }
        Some(&self.led_state[port])
    }

    /// Returns true if the EM transmitter is busy.
    pub fn is_busy(&self) -> bool {
        (self.read32(EmRegs::EM_CTL) & EmRegs::CTL_TM) != 0
    }

    /// Handles an EM interrupt (MR bit set in EM_CTL).
    pub fn handle_irq(&self) {
        // Clear MR by writing 1 to it.
        let ctl = self.read32(EmRegs::EM_CTL);
        if (ctl & EmRegs::CTL_MR) != 0 {
            self.write32(EmRegs::EM_CTL, EmRegs::CTL_MR);
        }
    }

    // ---- private helpers ----

    fn transmit_led(&self, msg: LedMessage) -> Result<()> {
        if self.is_busy() {
            return Err(Error::Busy);
        }
        // Write LED message header + payload into EM buffer.
        let buf_base = self.hba_base + self.em_buf_offset;
        // Header: [7:0] = message type, [15:8] = message length in DWORDs, [23:16] = reserved.
        let header: u32 = (EmMessageType::Led as u32) | (2 << 8);
        let ptr_h = buf_base as *mut u32;
        // SAFETY: hba_base + em_buf_offset is a valid mapped HBA MMIO EM buffer region.
        unsafe {
            core::ptr::write_volatile(ptr_h, header);
            core::ptr::write_volatile(ptr_h.add(1), msg.encode());
        }
        // Trigger transmission.
        self.write32(EmRegs::EM_CTL, EmRegs::CTL_TM);
        Ok(())
    }

    fn read32(&self, offset: usize) -> u32 {
        let ptr = (self.hba_base + offset) as *const u32;
        // SAFETY: hba_base is a valid mapped AHCI HBA MMIO region.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    fn write32(&self, offset: usize, val: u32) {
        let ptr = (self.hba_base + offset) as *mut u32;
        // SAFETY: hba_base is a valid mapped AHCI HBA MMIO region.
        unsafe { core::ptr::write_volatile(ptr, val) }
    }
}

impl Default for AhciEnclosureManager {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Returns a string description of an EM message type.
pub fn em_message_type_name(t: EmMessageType) -> &'static str {
    match t {
        EmMessageType::Led => "LED",
        EmMessageType::SafTe => "SAF-TE",
        EmMessageType::Ses2 => "SES-2",
        EmMessageType::Sgpio => "SGPIO",
    }
}
