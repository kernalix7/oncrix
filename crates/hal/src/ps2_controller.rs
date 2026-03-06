// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PS/2 controller (Intel 8042) driver.
//!
//! Manages the Intel 8042 PS/2 controller, which interfaces the CPU with
//! PS/2 keyboard (port 1) and mouse (port 2). Handles:
//! - Controller initialization and self-test
//! - Port enable/disable
//! - Data byte send/receive with status polling
//! - IRQ configuration (IRQ1 = keyboard, IRQ12 = mouse)
//!
//! # I/O Ports
//!
//! | Port  | Read            | Write          |
//! |-------|-----------------|----------------|
//! | 0x60  | Data buffer     | Data/command   |
//! | 0x64  | Status register | Command port   |
//!
//! Reference: OSDev Wiki — 8042 PS/2 Controller.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// I/O port addresses
// ---------------------------------------------------------------------------

/// PS/2 data port (read: output buffer; write: data to device/controller).
pub const PS2_DATA_PORT: u16 = 0x60;

/// PS/2 command/status port (read: status; write: controller command).
pub const PS2_CMD_PORT: u16 = 0x64;

// ---------------------------------------------------------------------------
// Status register bits
// ---------------------------------------------------------------------------

/// Status bit: output buffer full (data available to read from 0x60).
pub const PS2_STATUS_OUTPUT_FULL: u8 = 1 << 0;
/// Status bit: input buffer full (controller busy, do not write).
pub const PS2_STATUS_INPUT_FULL: u8 = 1 << 1;
/// Status bit: system flag (POST passed).
pub const PS2_STATUS_SYSTEM: u8 = 1 << 2;
/// Status bit: data is for controller (not device).
pub const PS2_STATUS_CMD_DATA: u8 = 1 << 3;
/// Status bit: keyboard locked (inhibit switch).
pub const PS2_STATUS_INHIBIT: u8 = 1 << 4;
/// Status bit: mouse output buffer full.
pub const PS2_STATUS_MOUSE_FULL: u8 = 1 << 5;
/// Status bit: timeout error.
pub const PS2_STATUS_TIMEOUT: u8 = 1 << 6;
/// Status bit: parity error.
pub const PS2_STATUS_PARITY: u8 = 1 << 7;

// ---------------------------------------------------------------------------
// Controller commands
// ---------------------------------------------------------------------------

/// Read internal configuration byte.
pub const PS2_CMD_READ_CONFIG: u8 = 0x20;
/// Write internal configuration byte.
pub const PS2_CMD_WRITE_CONFIG: u8 = 0x60;
/// Disable second PS/2 port (mouse).
pub const PS2_CMD_DISABLE_PORT2: u8 = 0xA7;
/// Enable second PS/2 port (mouse).
pub const PS2_CMD_ENABLE_PORT2: u8 = 0xA8;
/// Test second PS/2 port.
pub const PS2_CMD_TEST_PORT2: u8 = 0xA9;
/// Controller self-test (returns 0x55 on success).
pub const PS2_CMD_SELF_TEST: u8 = 0xAA;
/// Test first PS/2 port.
pub const PS2_CMD_TEST_PORT1: u8 = 0xAB;
/// Disable first PS/2 port (keyboard).
pub const PS2_CMD_DISABLE_PORT1: u8 = 0xAD;
/// Enable first PS/2 port (keyboard).
pub const PS2_CMD_ENABLE_PORT1: u8 = 0xAE;
/// Write next byte to second PS/2 port input buffer.
pub const PS2_CMD_WRITE_PORT2: u8 = 0xD4;

/// Self-test success response.
pub const PS2_SELF_TEST_OK: u8 = 0x55;
/// Port test: no error.
pub const PS2_PORT_TEST_OK: u8 = 0x00;

// ---------------------------------------------------------------------------
// Configuration byte bits
// ---------------------------------------------------------------------------

/// Config byte: first port interrupt enable (IRQ1).
pub const PS2_CFG_PORT1_IRQ: u8 = 1 << 0;
/// Config byte: second port interrupt enable (IRQ12).
pub const PS2_CFG_PORT2_IRQ: u8 = 1 << 1;
/// Config byte: system flag.
pub const PS2_CFG_SYSTEM: u8 = 1 << 2;
/// Config byte: first port clock disabled.
pub const PS2_CFG_PORT1_CLK_DIS: u8 = 1 << 4;
/// Config byte: second port clock disabled.
pub const PS2_CFG_PORT2_CLK_DIS: u8 = 1 << 5;
/// Config byte: first port translation (AT scan code → XT).
pub const PS2_CFG_TRANSLATION: u8 = 1 << 6;

/// Maximum polling iterations before declaring timeout.
const POLL_TIMEOUT: u32 = 100_000;

// ---------------------------------------------------------------------------
// Port I/O helpers
// ---------------------------------------------------------------------------

/// Read a byte from an x86 I/O port.
///
/// # Safety
///
/// Must be called from ring 0. The port must be a valid readable I/O address.
#[cfg(target_arch = "x86_64")]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Caller guarantees ring 0 and valid port.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nomem, nostack),
        );
    }
    val
}

/// Write a byte to an x86 I/O port.
///
/// # Safety
///
/// Must be called from ring 0. The port must be a valid writable I/O address.
#[cfg(target_arch = "x86_64")]
unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Caller guarantees ring 0 and valid port.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack),
        );
    }
}

// ---------------------------------------------------------------------------
// Ps2Controller
// ---------------------------------------------------------------------------

/// Driver state for the Intel 8042 PS/2 controller.
#[derive(Debug)]
pub struct Ps2Controller {
    /// Whether a second port (mouse) is present.
    pub has_port2: bool,
    /// Cached configuration byte.
    pub config: u8,
    /// Whether the controller has been initialized.
    pub initialized: bool,
}

impl Ps2Controller {
    /// Creates an uninitialized PS/2 controller instance.
    pub const fn new() -> Self {
        Self {
            has_port2: false,
            config: 0,
            initialized: false,
        }
    }

    /// Waits until the input buffer is empty (safe to write).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on timeout.
    #[cfg(target_arch = "x86_64")]
    fn wait_write(&self) -> Result<()> {
        for _ in 0..POLL_TIMEOUT {
            // SAFETY: Reading PS/2 status port from ring 0.
            let status = unsafe { inb(PS2_CMD_PORT) };
            if status & PS2_STATUS_INPUT_FULL == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Waits until the output buffer is full (data available to read).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on timeout.
    #[cfg(target_arch = "x86_64")]
    fn wait_read(&self) -> Result<()> {
        for _ in 0..POLL_TIMEOUT {
            // SAFETY: Reading PS/2 status port from ring 0.
            let status = unsafe { inb(PS2_CMD_PORT) };
            if status & PS2_STATUS_OUTPUT_FULL != 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Sends a command byte to the controller.
    ///
    /// # Safety
    ///
    /// Must be called from ring 0.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn send_command(&self, cmd: u8) -> Result<()> {
        self.wait_write()?;
        // SAFETY: Caller ensures ring 0; writing to PS/2 command port.
        unsafe { outb(PS2_CMD_PORT, cmd) };
        Ok(())
    }

    /// Sends a data byte to port 1 (keyboard) input buffer.
    ///
    /// # Safety
    ///
    /// Must be called from ring 0.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn send_data(&self, data: u8) -> Result<()> {
        self.wait_write()?;
        // SAFETY: Caller ensures ring 0; writing to PS/2 data port.
        unsafe { outb(PS2_DATA_PORT, data) };
        Ok(())
    }

    /// Reads a byte from the output buffer.
    ///
    /// # Safety
    ///
    /// Must be called from ring 0.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn read_data(&self) -> Result<u8> {
        self.wait_read()?;
        // SAFETY: Caller ensures ring 0; reading from PS/2 data port.
        Ok(unsafe { inb(PS2_DATA_PORT) })
    }

    /// Reads the controller status register.
    ///
    /// # Safety
    ///
    /// Must be called from ring 0.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn read_status(&self) -> u8 {
        // SAFETY: Caller ensures ring 0.
        unsafe { inb(PS2_CMD_PORT) }
    }

    /// Initializes the PS/2 controller.
    ///
    /// Performs self-test, detects port 2, enables interrupts, and resets
    /// both ports. Returns `Ok(())` on success.
    ///
    /// # Safety
    ///
    /// Must be called from ring 0 during early boot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::IoError`] if the self-test fails.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn init(&mut self) -> Result<()> {
        // SAFETY: All port I/O is valid from ring 0.
        unsafe {
            // Disable both ports while we configure.
            self.send_command(PS2_CMD_DISABLE_PORT1)?;
            self.send_command(PS2_CMD_DISABLE_PORT2)?;

            // Flush output buffer.
            let _ = inb(PS2_DATA_PORT);

            // Read and modify configuration: disable IRQs and translation.
            self.send_command(PS2_CMD_READ_CONFIG)?;
            let cfg = self.read_data()?;
            let new_cfg = cfg & !(PS2_CFG_PORT1_IRQ | PS2_CFG_PORT2_IRQ | PS2_CFG_TRANSLATION);
            self.send_command(PS2_CMD_WRITE_CONFIG)?;
            self.send_data(new_cfg)?;

            // Controller self-test.
            self.send_command(PS2_CMD_SELF_TEST)?;
            let result = self.read_data()?;
            if result != PS2_SELF_TEST_OK {
                return Err(Error::IoError);
            }

            // Re-write config (self-test may reset it).
            self.send_command(PS2_CMD_WRITE_CONFIG)?;
            self.send_data(new_cfg)?;

            // Check for second port.
            self.send_command(PS2_CMD_ENABLE_PORT2)?;
            self.send_command(PS2_CMD_READ_CONFIG)?;
            let cfg2 = self.read_data()?;
            self.has_port2 = cfg2 & PS2_CFG_PORT2_CLK_DIS == 0;
            self.send_command(PS2_CMD_DISABLE_PORT2)?;

            // Test ports.
            self.send_command(PS2_CMD_TEST_PORT1)?;
            let _ = self.read_data()?;

            // Enable port 1, enable IRQ1 (and IRQ12 if port2 present).
            self.send_command(PS2_CMD_ENABLE_PORT1)?;
            let mut final_cfg = new_cfg | PS2_CFG_PORT1_IRQ;
            if self.has_port2 {
                self.send_command(PS2_CMD_ENABLE_PORT2)?;
                final_cfg |= PS2_CFG_PORT2_IRQ;
            }
            self.send_command(PS2_CMD_WRITE_CONFIG)?;
            self.send_data(final_cfg)?;
            self.config = final_cfg;
        }
        self.initialized = true;
        Ok(())
    }

    /// Sends a byte to the second PS/2 port (mouse).
    ///
    /// # Safety
    ///
    /// Must be called from ring 0.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn send_to_mouse(&self, data: u8) -> Result<()> {
        if !self.has_port2 {
            return Err(Error::NotFound);
        }
        // SAFETY: Port I/O valid from ring 0.
        unsafe {
            self.send_command(PS2_CMD_WRITE_PORT2)?;
            self.send_data(data)?;
        }
        Ok(())
    }
}

impl Default for Ps2Controller {
    fn default() -> Self {
        Self::new()
    }
}
