// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PS/2 mouse driver.
//!
//! Implements the standard PS/2 mouse protocol used by the i8042 controller
//! found on PC-compatible systems. Supports basic two- and three-button mice
//! as well as the extended IntelliMouse (scroll wheel) protocol.

use oncrix_lib::{Error, Result};

/// PS/2 mouse commands.
const CMD_RESET: u8 = 0xFF;
const CMD_RESEND: u8 = 0xFE;
const CMD_SET_DEFAULTS: u8 = 0xF6;
const CMD_DISABLE_REPORTING: u8 = 0xF5;
const CMD_ENABLE_REPORTING: u8 = 0xF4;
const CMD_SET_SAMPLE_RATE: u8 = 0xF3;
const CMD_GET_DEVICE_ID: u8 = 0xF2;
const CMD_SET_REMOTE_MODE: u8 = 0xF0;
const CMD_SET_WRAP_MODE: u8 = 0xEE;
const CMD_RESET_WRAP_MODE: u8 = 0xEC;
const CMD_READ_DATA: u8 = 0xEB;
const CMD_SET_STREAM_MODE: u8 = 0xEA;
const CMD_STATUS_REQUEST: u8 = 0xE9;
const CMD_SET_RESOLUTION: u8 = 0xE8;
const CMD_SET_SCALE_2_1: u8 = 0xE7;
const CMD_SET_SCALE_1_1: u8 = 0xE6;

/// Mouse response codes.
const RESP_ACK: u8 = 0xFA;
const RESP_RESEND: u8 = 0xFE;
const RESP_BAT_OK: u8 = 0xAA;

/// Mouse device IDs.
const DEVICE_ID_STANDARD: u8 = 0x00;
const DEVICE_ID_INTELLIMOUSE: u8 = 0x03;
const DEVICE_ID_INTELLIMOUSE_EXPLORER: u8 = 0x04;

/// Mouse packet size by device type.
const PACKET_SIZE_STANDARD: usize = 3;
const PACKET_SIZE_INTELLIMOUSE: usize = 4;

/// Status byte bit definitions (first byte of every packet).
const STATUS_LEFT_BTN: u8 = 1 << 0;
const STATUS_RIGHT_BTN: u8 = 1 << 1;
const STATUS_MIDDLE_BTN: u8 = 1 << 2;
const STATUS_ALWAYS_ONE: u8 = 1 << 3;
const STATUS_X_SIGN: u8 = 1 << 4;
const STATUS_Y_SIGN: u8 = 1 << 5;
const STATUS_X_OVF: u8 = 1 << 6;
const STATUS_Y_OVF: u8 = 1 << 7;

/// I/O port addresses for the i8042 controller.
const PORT_DATA: u16 = 0x60;
const PORT_STATUS: u16 = 0x64;
const PORT_CMD: u16 = 0x64;

/// i8042 status register bits.
const STATUS_OBF: u8 = 1 << 0; // Output buffer full (data ready to read)
const STATUS_IBF: u8 = 1 << 1; // Input buffer full (controller busy)
const STATUS_AUX: u8 = 1 << 5; // Auxiliary (mouse) data in OBF

/// i8042 commands used to direct data to the mouse.
const CTRL_CMD_WRITE_MOUSE: u8 = 0xD4;

/// Maximum number of bytes in the receive packet buffer.
const MAX_PACKET_SIZE: usize = 4;

/// Decoded mouse event.
#[derive(Clone, Copy, Debug, Default)]
pub struct MouseEvent {
    /// Relative X movement (left = negative).
    pub dx: i16,
    /// Relative Y movement (down = negative in HID conventions).
    pub dy: i16,
    /// Scroll wheel delta (positive = scroll up).
    pub dz: i8,
    /// Left button pressed.
    pub left: bool,
    /// Right button pressed.
    pub right: bool,
    /// Middle button pressed.
    pub middle: bool,
}

/// Mouse protocol type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MouseProtocol {
    /// Standard 2/3-button mouse (3-byte packets).
    Standard,
    /// IntelliMouse with scroll wheel (4-byte packets).
    IntelliMouse,
    /// IntelliMouse Explorer with 5 buttons (4-byte packets).
    IntelliMouseExplorer,
}

/// PS/2 mouse driver.
pub struct Ps2Mouse {
    /// Protocol in use.
    protocol: MouseProtocol,
    /// Packet accumulator buffer.
    packet_buf: [u8; MAX_PACKET_SIZE],
    /// Number of bytes received in the current packet.
    packet_len: usize,
    /// Expected size of a complete packet.
    expected_size: usize,
    /// Reporting is enabled.
    reporting: bool,
}

impl Ps2Mouse {
    /// Create a new PS/2 mouse driver.
    pub fn new() -> Self {
        Self {
            protocol: MouseProtocol::Standard,
            packet_buf: [0u8; MAX_PACKET_SIZE],
            packet_len: 0,
            expected_size: PACKET_SIZE_STANDARD,
            reporting: false,
        }
    }

    /// Initialize the mouse: reset, detect protocol, enable reporting.
    pub fn init(&mut self) -> Result<()> {
        self.reset()?;
        self.detect_protocol()?;
        self.enable_reporting()?;
        Ok(())
    }

    /// Perform a hardware reset and wait for BAT completion.
    fn reset(&mut self) -> Result<()> {
        self.send_command(CMD_RESET)?;
        // After reset the mouse sends BAT OK (0xAA) and then device ID.
        let bat = self.read_byte()?;
        if bat != RESP_BAT_OK {
            return Err(Error::IoError);
        }
        let _id = self.read_byte()?; // Device ID (0x00 for standard).
        Ok(())
    }

    /// Attempt to negotiate IntelliMouse or IntelliMouse Explorer protocol.
    fn detect_protocol(&mut self) -> Result<()> {
        // Magic sequence to unlock scroll wheel: rate 200, 100, 80.
        self.set_sample_rate(200)?;
        self.set_sample_rate(100)?;
        self.set_sample_rate(80)?;
        let id = self.get_device_id()?;
        if id == DEVICE_ID_INTELLIMOUSE {
            // Attempt to enable 5-button mode: rate 200, 200, 80.
            self.set_sample_rate(200)?;
            self.set_sample_rate(200)?;
            self.set_sample_rate(80)?;
            let id2 = self.get_device_id()?;
            if id2 == DEVICE_ID_INTELLIMOUSE_EXPLORER {
                self.protocol = MouseProtocol::IntelliMouseExplorer;
            } else {
                self.protocol = MouseProtocol::IntelliMouse;
            }
            self.expected_size = PACKET_SIZE_INTELLIMOUSE;
        }
        Ok(())
    }

    /// Enable data reporting (stream mode).
    fn enable_reporting(&mut self) -> Result<()> {
        self.send_command(CMD_ENABLE_REPORTING)?;
        let ack = self.read_byte()?;
        if ack != RESP_ACK {
            return Err(Error::IoError);
        }
        self.reporting = true;
        Ok(())
    }

    /// Disable data reporting.
    pub fn disable_reporting(&mut self) -> Result<()> {
        self.send_command(CMD_DISABLE_REPORTING)?;
        let ack = self.read_byte()?;
        if ack != RESP_ACK {
            return Err(Error::IoError);
        }
        self.reporting = false;
        Ok(())
    }

    /// Set the mouse sample rate (samples per second).
    pub fn set_sample_rate(&mut self, rate: u8) -> Result<()> {
        self.send_command(CMD_SET_SAMPLE_RATE)?;
        let ack = self.read_byte()?;
        if ack != RESP_ACK {
            return Err(Error::IoError);
        }
        self.write_data(rate)?;
        let ack2 = self.read_byte()?;
        if ack2 != RESP_ACK {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Query the device ID from the mouse.
    fn get_device_id(&mut self) -> Result<u8> {
        self.send_command(CMD_GET_DEVICE_ID)?;
        let ack = self.read_byte()?;
        if ack != RESP_ACK {
            return Err(Error::IoError);
        }
        self.read_byte()
    }

    /// Feed one received byte into the packet accumulator.
    ///
    /// Returns `Some(MouseEvent)` when a complete packet is assembled,
    /// or `None` if more bytes are needed.
    pub fn receive_byte(&mut self, byte: u8) -> Option<MouseEvent> {
        self.packet_buf[self.packet_len] = byte;
        self.packet_len += 1;
        if self.packet_len >= self.expected_size {
            let event = self.decode_packet();
            self.packet_len = 0;
            Some(event)
        } else {
            None
        }
    }

    /// Decode the accumulated packet buffer into a `MouseEvent`.
    fn decode_packet(&self) -> MouseEvent {
        let status = self.packet_buf[0];
        let raw_dx = self.packet_buf[1] as i16;
        let raw_dy = self.packet_buf[2] as i16;

        // Apply sign extension using the sign bits in the status byte.
        let dx = if (status & STATUS_X_SIGN) != 0 {
            raw_dx - 256
        } else {
            raw_dx
        };
        let dy = if (status & STATUS_Y_SIGN) != 0 {
            raw_dy - 256
        } else {
            raw_dy
        };

        let dz: i8 = if self.protocol != MouseProtocol::Standard && self.packet_len >= 4 {
            let z_raw = self.packet_buf[3] & 0x0F;
            if z_raw >= 8 {
                z_raw as i8 - 16
            } else {
                z_raw as i8
            }
        } else {
            0
        };

        MouseEvent {
            dx,
            dy: -dy, // Y axis is inverted in PS/2 relative to screen coordinates.
            dz,
            left: (status & STATUS_LEFT_BTN) != 0,
            right: (status & STATUS_RIGHT_BTN) != 0,
            middle: (status & STATUS_MIDDLE_BTN) != 0,
        }
    }

    /// Return the negotiated mouse protocol.
    pub fn protocol(&self) -> MouseProtocol {
        self.protocol
    }

    // --- Low-level i8042 helpers ---

    /// Send a command byte to the mouse via the i8042 controller.
    fn send_command(&mut self, cmd: u8) -> Result<()> {
        self.wait_write()?;
        self.write_cmd(CTRL_CMD_WRITE_MOUSE);
        self.wait_write()?;
        self.write_data(cmd)
    }

    /// Write a data byte directly to the data port.
    fn write_data(&mut self, val: u8) -> Result<()> {
        self.wait_write()?;
        #[cfg(target_arch = "x86_64")]
        // SAFETY: PORT_DATA (0x60) is the i8042 data port; writing here sends
        // data to the currently selected PS/2 device.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") PORT_DATA,
                in("al") val,
                options(nomem, nostack)
            );
        }
        Ok(())
    }

    /// Write a command byte to the i8042 command port.
    fn write_cmd(&self, val: u8) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: PORT_CMD (0x64) is the i8042 command port; this is a
        // standard PC hardware interface.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") PORT_CMD,
                in("al") val,
                options(nomem, nostack)
            );
        }
    }

    /// Read one byte from the i8042 data port.
    fn read_byte(&self) -> Result<u8> {
        self.wait_read()?;
        #[cfg(target_arch = "x86_64")]
        {
            let val: u8;
            // SAFETY: PORT_DATA (0x60) is the i8042 data port; reading returns
            // a byte previously placed by the controller or device.
            unsafe {
                core::arch::asm!(
                    "in al, dx",
                    in("dx") PORT_DATA,
                    out("al") val,
                    options(nomem, nostack)
                );
            }
            return Ok(val);
        }
        #[allow(unreachable_code)]
        Err(Error::NotImplemented)
    }

    /// Spin until the i8042 output buffer contains data (OBF = 1).
    fn wait_read(&self) -> Result<()> {
        let mut tries = 0u32;
        loop {
            let status = self.read_status();
            if (status & STATUS_OBF) != 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Spin until the i8042 input buffer is empty (IBF = 0).
    fn wait_write(&self) -> Result<()> {
        let mut tries = 0u32;
        loop {
            let status = self.read_status();
            if (status & STATUS_IBF) == 0 {
                return Ok(());
            }
            tries += 1;
            if tries > 100_000 {
                return Err(Error::Busy);
            }
            core::hint::spin_loop();
        }
    }

    /// Read the i8042 status register.
    fn read_status(&self) -> u8 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u8;
            // SAFETY: PORT_STATUS (0x64) is the i8042 status register.
            unsafe {
                core::arch::asm!(
                    "in al, dx",
                    in("dx") PORT_STATUS,
                    out("al") val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
        #[allow(unreachable_code)]
        0
    }
}

impl Default for Ps2Mouse {
    fn default() -> Self {
        Self::new()
    }
}
